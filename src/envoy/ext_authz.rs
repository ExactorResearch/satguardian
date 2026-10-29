//! Envoy External Authorization (ext_authz) HTTP Filter Service.
//! Implements sub-millisecond AST SAT verification and formal causal proof generation
//! compatible with Envoy's envoy.filters.http.ext_authz filter.

use crate::ast::features::FeatureBinarizer;
use crate::ast::lexer::AstLexer;
use crate::engine::SatguardianSatEngine;
use crate::ledger::{AuditRecord, SqliteLedger};
use crate::stateful::StatefulRateLimiter;
use crate::types::{AttackDecision, HttpRequestPayload, ProofChain};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};

/// Shared state for the Envoy ext_authz HTTP service.
#[derive(Clone)]
pub struct EnvoyAuthzState {
    pub sat_engine: Arc<SatguardianSatEngine>,
    pub ledger: SqliteLedger,
    pub rate_limiter: Arc<StatefulRateLimiter>,
    pub mode: String, // "block" or "monitor"

    pub total_checks: Arc<AtomicU64>,
    pub blocked_checks: Arc<AtomicU64>,
    pub allowed_checks: Arc<AtomicU64>,
}

impl EnvoyAuthzState {
    pub fn new(
        sat_engine: Arc<SatguardianSatEngine>,
        ledger: SqliteLedger,
        rate_limiter: Arc<StatefulRateLimiter>,
        mode: String,
    ) -> Self {
        Self {
            sat_engine,
            ledger,
            rate_limiter,
            mode,
            total_checks: Arc::new(AtomicU64::new(0)),
            blocked_checks: Arc::new(AtomicU64::new(0)),
            allowed_checks: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Creates an Axum router serving the Envoy ext_authz authorization endpoint.
pub fn create_envoy_authz_router(state: EnvoyAuthzState) -> Router {
    Router::new()
        .route("/ext_authz", any(handle_envoy_authz_check))
        .route("/api/waf/check", any(handle_envoy_authz_check))
        .fallback(handle_envoy_authz_check)
        .with_state(state)
}

/// Handles incoming ext_authz check requests dispatched by Envoy.
async fn handle_envoy_authz_check(
    State(state): State<EnvoyAuthzState>,
    client_addr: Option<ConnectInfo<SocketAddr>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let t_start = Instant::now();
    state.total_checks.fetch_add(1, Ordering::Relaxed);

    // 1. Resolve effective request URI & method from Envoy headers if forwarded
    let effective_method = headers
        .get("x-envoy-original-method")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| method.as_str())
        .to_uppercase();

    let raw_path = headers
        .get("x-envoy-original-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_else(|| uri.path());

    let (path, query_string) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_path.to_string(), uri.query().unwrap_or("").to_string()),
    };

    // 2. Extract Client IP
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| {
            client_addr
                .map(|c| c.0.ip().to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string())
        });

    // 3. Extract Headers map
    let mut headers_map = HashMap::with_capacity(headers.len());
    for (name, val) in &headers {
        if let Ok(v_str) = val.to_str() {
            headers_map.insert(name.as_str().to_ascii_lowercase(), v_str.to_string());
        }
    }

    let body_str = String::from_utf8_lossy(&body).into_owned();

    // 4. Construct Payload for Exactor SAT Engine
    let payload = HttpRequestPayload {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        method: effective_method,
        path,
        query_string,
        headers: headers_map,
        body: body_str,
        client_ip: Some(client_ip.clone()),
    };

    // 5. Stateful & Behavioral Sliding Window Inspection
    let stateful_verdict = state.rate_limiter.check_and_update(&payload);

    // 6. Sub-millisecond SAT Invariant Evaluation (< 0.05 ms)
    let proof: ProofChain = state
        .sat_engine
        .evaluate_payload_with_verdict(&payload, Some(&stateful_verdict));

    let eval_us = t_start.elapsed().as_secs_f64() * 1_000_000.0;

    // 7. Non-blocking asynchronous WAL ledger logging
    let mut tokens = AstLexer::tokenize_request(&payload);
    if stateful_verdict.is_rate_limit {
        tokens.has_stateful_rate_limit = true;
    }
    if stateful_verdict.is_credential_stuffing {
        tokens.has_stateful_credential_stuffing = true;
    }
    let fv = FeatureBinarizer::binarize(&payload, &tokens);
    state.ledger.log_event(AuditRecord {
        request_id: payload.id.clone(),
        client_ip: payload.client_ip.clone(),
        method: payload.method.clone(),
        path: payload.path.clone(),
        query_string: payload.query_string.clone(),
        proof: proof.clone(),
        minterm: fv.as_minterm(),
    });

    let should_block = state.mode == "block" && proof.action == AttackDecision::Block;

    if should_block {
        state.blocked_checks.fetch_add(1, Ordering::Relaxed);
        let rule_id = proof
            .matched_rules
            .first()
            .map(|r| r.rule_id.as_str())
            .unwrap_or("SAT-VIOLATION");

        warn!(
            "🛑 [ENVOY-SAT-BLOCK] [{}] IP: {} Category: {} Rule: {} ({:.1} µs)",
            payload.id,
            client_ip,
            proof.category,
            rule_id,
            eval_us
        );

        let error_body = serde_json::json!({
            "status": "BLOCKED",
            "code": 403,
            "action": "DENY",
            "event_id": payload.id,
            "category": proof.category.as_str(),
            "category_name": proof.category.display_name(),
            "violated_rule": rule_id,
            "rule_match_details": proof.rule_match_details,
            "decision_reason": proof.decision_reason,
            "active_tokens": proof.active_tokens,
            "latency_us": eval_us,
            "engine": "Envoy SAT Security Module (Powered by SATGuardian Core)"
        });

        let mut res = (StatusCode::FORBIDDEN, error_body.to_string()).into_response();
        let headers = res.headers_mut();
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        // Envoy-native headers
        headers.insert("x-envoy-waf-blocked", HeaderValue::from_static("true"));
        headers.insert(
            "x-envoy-waf-category",
            HeaderValue::from_str(proof.category.as_str()).unwrap_or(HeaderValue::from_static("unknown")),
        );
        headers.insert(
            "x-envoy-waf-rule",
            HeaderValue::from_str(rule_id).unwrap_or(HeaderValue::from_static("sat")),
        );
        headers.insert(
            "x-envoy-waf-event-id",
            HeaderValue::from_str(&payload.id).unwrap_or(HeaderValue::from_static("event")),
        );
        headers.insert(
            "x-envoy-waf-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );

        // SATGuardian provider headers
        headers.insert("x-satguardian-blocked", HeaderValue::from_static("true"));
        headers.insert(
            "x-satguardian-category",
            HeaderValue::from_str(proof.category.as_str()).unwrap_or(HeaderValue::from_static("unknown")),
        );
        headers.insert(
            "x-satguardian-rule",
            HeaderValue::from_str(rule_id).unwrap_or(HeaderValue::from_static("sat")),
        );
        headers.insert(
            "x-satguardian-event-id",
            HeaderValue::from_str(&payload.id).unwrap_or(HeaderValue::from_static("event")),
        );
        headers.insert(
            "x-satguardian-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );

        // Legacy compatibility headers
        headers.insert("x-exactor-blocked", HeaderValue::from_static("true"));
        headers.insert(
            "x-exactor-category",
            HeaderValue::from_str(proof.category.as_str()).unwrap_or(HeaderValue::from_static("unknown")),
        );
        headers.insert(
            "x-exactor-rule",
            HeaderValue::from_str(rule_id).unwrap_or(HeaderValue::from_static("sat")),
        );
        headers.insert(
            "x-exactor-event-id",
            HeaderValue::from_str(&payload.id).unwrap_or(HeaderValue::from_static("event")),
        );
        headers.insert(
            "x-exactor-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );
        res
    } else {
        state.allowed_checks.fetch_add(1, Ordering::Relaxed);
        debug!(
            "✅ [ENVOY-SAT-ALLOW] [{}] Path: {} ({:.1} µs)",
            payload.id, payload.path, eval_us
        );

        let mut res = (StatusCode::OK, "").into_response();
        let headers = res.headers_mut();
        headers.insert("x-envoy-waf-verified", HeaderValue::from_static("true"));
        headers.insert("x-satguardian-verified", HeaderValue::from_static("true"));
        headers.insert("x-exactor-verified", HeaderValue::from_static("true"));
        headers.insert(
            "x-envoy-waf-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );
        headers.insert(
            "x-satguardian-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );
        headers.insert(
            "x-exactor-latency-us",
            HeaderValue::from_str(&format!("{:.1}", eval_us))
                .unwrap_or(HeaderValue::from_static("0.0")),
        );
        res
    }
}

/// Serves the Envoy ext_authz HTTP verification router over a Unix Domain Socket (UDS).
/// Provides ultra-low-latency IPC (< 15 µs) for local Envoy sidecar deployments.
#[cfg(unix)]
pub async fn serve_uds(
    app: Router,
    socket_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tokio::net::UnixListener;
    use tower::Service;

    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(target: "satguardian::envoy", "Envoy ext_authz UDS service ready on unix://{}", socket_path);

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let app = app.clone();

        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let mut app = app.clone();
                async move { app.call(req).await }
            });

            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(target: "satguardian::envoy", "UDS connection closed: {:?}", err);
            }
        });
    }
}

