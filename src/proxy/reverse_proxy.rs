use crate::ast::features::FeatureBinarizer;
use crate::ast::lexer::AstLexer;
use crate::cloud::ExactorCloudClient;
use crate::config::WafConfig;
use crate::engine::ExactorSatEngine;
use crate::ledger::{AuditRecord, SqliteLedger};
use crate::stateful::StatefulRateLimiter;
use crate::types::{AttackDecision, HttpRequestPayload, ProofChain};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use http_body_util::BodyExt;
use reqwest::Client;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, warn};

pub struct ProxyState {
    pub config: WafConfig,
    pub engine: Arc<ExactorSatEngine>,
    pub ledger: SqliteLedger,
    pub stateful_limiter: Arc<StatefulRateLimiter>,
    pub cloud_client: ExactorCloudClient,
    pub http_client: Client,
    pub start_time: Instant,
    pub counter_total: AtomicU64,
    pub counter_blocked: AtomicU64,
    pub counter_allowed: AtomicU64,
    pub sum_latency_us: AtomicU64,
}

/// The core Reverse Proxy request handler.
pub async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    let method = parts.method.to_string();
    let uri = parts.uri.clone();
    let path = uri.path().to_string();
    let query_string = uri.query().unwrap_or("").to_string();

    let mut headers_map = HashMap::new();
    for (k, v) in &parts.headers {
        if let Ok(v_str) = v.to_str() {
            headers_map.insert(k.as_str().to_ascii_lowercase(), v_str.to_string());
        }
    }

    // Read inbound request body (up to 2MB)
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!(target: "exactor::proxy", "Failed to read request body: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read request body").into_response();
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let payload = HttpRequestPayload {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        method: method.clone(),
        path: path.clone(),
        query_string: query_string.clone(),
        headers: headers_map.clone(),
        body: body_str,
        client_ip: Some(addr.ip().to_string()),
    };

    // 1. Stateful Behavioral & Sliding Window Rate Limiting
    let stateful_verdict = state.stateful_limiter.check_and_update(&payload);

    // 2. Sub-millisecond Fast-Path Evaluation (< 0.05 ms)
    let proof: ProofChain = state.engine.evaluate_payload_with_verdict(&payload, Some(&stateful_verdict));

    // Compute minterm for anomaly / ledger tracking
    let mut tokens = AstLexer::tokenize_request(&payload);
    if stateful_verdict.is_rate_limit {
        tokens.has_stateful_rate_limit = true;
    }
    if stateful_verdict.is_credential_stuffing {
        tokens.has_stateful_credential_stuffing = true;
    }
    let fv = FeatureBinarizer::binarize(&payload, &tokens);
    let minterm = fv.as_minterm();

    // Telemetry update
    state.counter_total.fetch_add(1, Ordering::Relaxed);
    state.sum_latency_us.fetch_add(proof.execution_time_us as u64, Ordering::Relaxed);

    // Non-blocking asynchronous WAL ledger logging
    state.ledger.log_event(AuditRecord {
        request_id: payload.id.clone(),
        client_ip: payload.client_ip.clone(),
        method: method.clone(),
        path: path.clone(),
        query_string: query_string.clone(),
        proof: proof.clone(),
        minterm,
    });

    // Check action
    if proof.action == AttackDecision::Block && state.config.mode != "monitor" {
        state.counter_blocked.fetch_add(1, Ordering::Relaxed);
        warn!(
            target: "exactor::proxy",
            req_id = %payload.id,
            action = "BLOCK",
            category = %proof.category,
            latency_us = proof.execution_time_us,
            proof = %proof.causal_proof,
            "Attack blocked at perimeter"
        );

        // Modo Silencioso / Stealth vs Modo Verbose de Debugging
        if state.config.stealth_mode {
            // En modo stealth, no revelamos reglas violadas, categorías ni latencias en headers
            let custom_body = state.config.stealth_block_body.as_deref().unwrap_or(
                "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
            );
            return (
                StatusCode::FORBIDDEN,
                [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                custom_body.to_string(),
            ).into_response();
        }

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("X-Exactor-Action", HeaderValue::from_static("BLOCK"));
        if let Ok(v) = HeaderValue::from_str(proof.category.as_str()) {
            resp_headers.insert("X-Exactor-Category", v);
        }
        if let Ok(v) = HeaderValue::from_str(&format!("{:.2}", proof.execution_time_us)) {
            resp_headers.insert("X-Exactor-Latency-Us", v);
        }
        if let Ok(v) = HeaderValue::from_str(&proof.causal_proof) {
            resp_headers.insert("X-Exactor-Proof", v);
        }

        let body_json = serde_json::json!({
            "error": "Request blocked by Exactor WAF Guardian",
            "request_id": payload.id,
            "action": "BLOCK",
            "category": proof.category.as_str(),
            "execution_path": format!("{:?}", proof.execution_path),
            "latency_us": proof.execution_time_us,
            "causal_proof": proof.causal_proof,
            "formal_proof_latex": proof.formal_proof_latex,
        });

        return (StatusCode::FORBIDDEN, resp_headers, Json(body_json)).into_response();
    }

    state.counter_allowed.fetch_add(1, Ordering::Relaxed);
    debug!(
        target: "exactor::proxy",
        req_id = %payload.id,
        action = "ALLOW",
        latency_us = proof.execution_time_us,
        "Forwarding request to upstream backend"
    );

    // Construct upstream proxy request
    let upstream_base = state.config.upstream_url.trim_end_matches('/');
    let target_url = if query_string.is_empty() {
        format!("{}{}", upstream_base, path)
    } else {
        format!("{}{}?{}", upstream_base, path, query_string)
    };

    let mut client_req = state
        .http_client
        .request(parts.method, &target_url)
        .body(body_bytes);

    // Forward original headers
    for (k, v) in &parts.headers {
        let kl = k.as_str().to_ascii_lowercase();
        if kl != "host" && kl != "connection" && kl != "content-length" {
            client_req = client_req.header(k, v);
        }
    }

    // Add Exactor security verification headers
    client_req = client_req
        .header("X-Exactor-WAF", "ALLOW")
        .header("X-Exactor-Latency-Us", format!("{:.2}", proof.execution_time_us))
        .header("X-Exactor-Request-Id", &payload.id);

    match client_req.send().await {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();
            let mut res_builder = Response::builder().status(status);

            for (k, v) in upstream_resp.headers() {
                res_builder = res_builder.header(k, v);
            }

            res_builder = res_builder
                .header("X-Exactor-Protected", "true")
                .header("X-Exactor-Latency-Us", format!("{:.2}", proof.execution_time_us));

            let bytes = upstream_resp.bytes().await.unwrap_or_default();
            res_builder
                .body(Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(err) => {
            error!(
                target: "exactor::proxy",
                target_url = %target_url,
                error = %err,
                "Failed to reach upstream server"
            );
            (
                StatusCode::BAD_GATEWAY,
                format!("Exactor WAF Guardian: Bad Gateway to upstream {}: {}", target_url, err),
            )
                .into_response()
        }
    }
}
