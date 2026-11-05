use crate::ast::features::FeatureBinarizer;
use crate::ast::lexer::AstLexer;
use crate::cloud::ExactorCloudClient;
use crate::config::WafConfig;
use crate::engine::ExactorSatEngine;
use crate::ledger::{AuditRecord, SqliteLedger};
use crate::metrics::LatencyHistogram;
use crate::proxy::client_ip::{resolve_client_ip, TrustedProxies};
use crate::stateful::StatefulRateLimiter;
use crate::types::{AttackDecision, HttpRequestPayload, ProofChain};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
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
    pub trusted_proxies: TrustedProxies,
    pub latency_histogram: LatencyHistogram,
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

    let max_body = state.config.max_body_bytes;
    if let Some(content_length) = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if content_length > max_body {
            return payload_too_large(max_body);
        }
    }

    let body_bytes = match to_bytes(body, max_body).await {
        Ok(collected) => collected,
        Err(e) => {
            error!(target: "satguardian::proxy", "Failed to read request body: {}", e);
            return payload_too_large(max_body);
        }
    };
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    let client_ip = resolve_client_ip(addr.ip(), &parts.headers, &state.trusted_proxies);

    let payload = HttpRequestPayload {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        method: method.clone(),
        path: path.clone(),
        query_string: query_string.clone(),
        headers: headers_map.clone(),
        body: body_str,
        client_ip: Some(client_ip.clone()),
    };

    // 1. Stateful Behavioral & Sliding Window Rate Limiting
    let stateful_verdict = state.stateful_limiter.check_and_update(&payload);

    // 2. Fast-path bitmask evaluation (in-memory p50 ~20 µs on the pinned corpus)
    let proof: ProofChain = state
        .engine
        .evaluate_payload_with_verdict(&payload, Some(&stateful_verdict));

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
    state
        .sum_latency_us
        .fetch_add(proof.execution_time_us as u64, Ordering::Relaxed);
    state
        .latency_histogram
        .observe(proof.execution_time_us as u64);

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
            target: "satguardian::proxy",
            req_id = %payload.id,
            action = "BLOCK",
            category = %proof.category,
            latency_us = proof.execution_time_us,
            proof = %proof.rule_match_details,
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
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                custom_body.to_string(),
            )
                .into_response();
        }

        let mut resp_headers = HeaderMap::new();
        resp_headers.insert("X-SATGuardian-Action", HeaderValue::from_static("BLOCK"));
        if let Ok(v) = HeaderValue::from_str(proof.category.as_str()) {
            resp_headers.insert("X-SATGuardian-Category", v);
        }
        if let Ok(v) = HeaderValue::from_str(&format!("{:.2}", proof.execution_time_us)) {
            resp_headers.insert("X-SATGuardian-Latency-Us", v);
        }
        if let Ok(v) = HeaderValue::from_str(&proof.rule_match_details) {
            resp_headers.insert("X-SATGuardian-Proof", v);
        }

        let body_json = serde_json::json!({
            "error": "Request blocked by SATGuardian Edge WAF",
            "request_id": payload.id,
            "action": "BLOCK",
            "category": proof.category.as_str(),
            "execution_path": format!("{:?}", proof.execution_path),
            "latency_us": proof.execution_time_us,
            "rule_match_details": proof.rule_match_details,
            "decision_reason": proof.decision_reason,
        });

        return (StatusCode::FORBIDDEN, resp_headers, Json(body_json)).into_response();
    }

    state.counter_allowed.fetch_add(1, Ordering::Relaxed);
    debug!(
        target: "satguardian::proxy",
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

    // Forward original headers, dropping hop-by-hop and client-supplied identity headers.
    let request_connection_tokens = connection_tokens(&parts.headers);
    for (k, v) in &parts.headers {
        let kl = k.as_str().to_ascii_lowercase();
        if should_strip_request_header(&kl, &request_connection_tokens) {
            continue;
        }
        client_req = client_req.header(k, v);
    }

    client_req = client_req
        .header("x-forwarded-for", client_ip.as_str())
        .header("x-real-ip", client_ip.as_str())
        .header("X-SATGuardian-WAF", "ALLOW")
        .header("X-SATGuardian-Request-Id", &payload.id);

    if !state.config.stealth_mode {
        client_req = client_req.header(
            "X-SATGuardian-Latency-Us",
            format!("{:.2}", proof.execution_time_us),
        );
    }

    match client_req.send().await {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();
            let mut res_builder = Response::builder().status(status);

            let response_connection_tokens = connection_tokens(upstream_resp.headers());
            for (k, v) in upstream_resp.headers() {
                let kl = k.as_str().to_ascii_lowercase();
                if should_strip_response_header(&kl, &response_connection_tokens) {
                    continue;
                }
                res_builder = res_builder.header(k, v);
            }

            if !state.config.stealth_mode {
                res_builder = res_builder
                    .header("X-SATGuardian-Protected", "true")
                    .header(
                        "X-SATGuardian-Latency-Us",
                        format!("{:.2}", proof.execution_time_us),
                    );
            }

            let body_stream = upstream_resp.bytes_stream();
            res_builder
                .body(Body::from_stream(body_stream))
                .unwrap_or_else(|e| {
                    error!(target: "satguardian::proxy", "Failed to build upstream response: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })
        }
        Err(err) => {
            error!(
                target: "satguardian::proxy",
                target_url = %target_url,
                error = %err,
                "Failed to reach upstream server"
            );
            if state.config.stealth_mode {
                (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    format!(
                        "Exactor WAF Guardian: Bad Gateway to upstream {}: {}",
                        target_url, err
                    ),
                )
                    .into_response()
            }
        }
    }
}

fn payload_too_large(max_body: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!(
            "Request body exceeds the configured limit of {} bytes",
            max_body
        ),
    )
        .into_response()
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn should_strip_request_header(name: &str, connection_tokens: &[String]) -> bool {
    const ALWAYS_STRIP: &[&str] = &[
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "true-client-ip",
    ];
    ALWAYS_STRIP.contains(&name) || connection_tokens.iter().any(|t| t == name)
}

fn should_strip_response_header(name: &str, connection_tokens: &[String]) -> bool {
    const ALWAYS_STRIP: &[&str] = &[
        "content-length",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    ALWAYS_STRIP.contains(&name) || connection_tokens.iter().any(|t| t == name)
}
