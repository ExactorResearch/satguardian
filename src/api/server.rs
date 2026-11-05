use crate::ast::features::FeatureBinarizer;
use crate::cloud::SimplifyRequest;
use crate::config::{CustomBusinessRule, IslandsConfig};
use crate::proxy::ProxyState;
use crate::types::{HttpRequestPayload, ProofChain, WafMetricsSnapshot};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
pub struct InspectDto {
    #[serde(default = "default_get")]
    pub method: String,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub query_string: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
}

fn default_get() -> String {
    "GET".to_string()
}

fn default_path() -> String {
    "/".to_string()
}

pub fn create_api_router(state: Arc<ProxyState>) -> Router {
    let protected = Router::new()
        .route("/api/waf/inspect", post(inspect_payload))
        .route("/api/waf/metrics", get(get_metrics))
        .route("/api/waf/rules", get(get_rules))
        .route("/api/waf/islands", get(get_islands))
        .route(
            "/api/waf/islands/config",
            get(get_islands_config).post(update_islands_config),
        )
        .route(
            "/api/waf/rules/customer",
            get(get_customer_rules).post(add_customer_rule),
        )
        .route("/api/waf/rules/customer/:id", delete(delete_customer_rule))
        .route("/api/waf/sync-simplify", post(trigger_sync_simplify))
        .route("/api/waf/clauses/pending", get(get_pending_clauses))
        .route(
            "/api/waf/clauses/:id/apply",
            post(apply_pending_clause),
        )
        .route("/api/waf/clauses/:id", delete(reject_pending_clause))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_token,
        ));

    Router::new()
        .route("/health", get(health_check))
        .route("/livez", get(health_check))
        .merge(protected)
        .with_state(state)
}

async fn require_admin_token(
    State(state): State<Arc<ProxyState>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(expected) = state
        .config
        .admin_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "management_api_disabled",
                "message": "Set SATGUARDIAN_ADMIN_TOKEN (or WAF_ADMIN_TOKEN) to enable the management API"
            })),
        )
            .into_response();
    };

    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    match provided {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(req).await
        }
        _ => {
            let mut res = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "admin_auth_required" })),
            )
                .into_response();
            res.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            res
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "satguardian",
        "version": env!("CARGO_PKG_VERSION"),
        "methodology": "Deterministic SAT Neuro-Symbolic Cyber-Defense"
    }))
}

async fn inspect_payload(
    State(state): State<Arc<ProxyState>>,
    Json(dto): Json<InspectDto>,
) -> impl IntoResponse {
    let payload = HttpRequestPayload {
        id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        method: dto.method,
        path: dto.path,
        query_string: dto.query_string,
        headers: dto.headers,
        body: dto.body,
        client_ip: None,
    };

    let proof: ProofChain = state.engine.evaluate_payload(&payload);
    Json(proof)
}

async fn get_metrics(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let total = state.counter_total.load(Ordering::Relaxed);
    let blocked = state.counter_blocked.load(Ordering::Relaxed);
    let allowed = state.counter_allowed.load(Ordering::Relaxed);

    let pending = state.ledger.count_pending_anomalies().await;

    let metrics = WafMetricsSnapshot {
        total_requests: total,
        blocked_requests: blocked,
        allowed_requests: allowed,
        avg_latency_us: (state.latency_histogram.avg_us() * 100.0).round() / 100.0,
        p99_latency_us: state.latency_histogram.percentile_us(0.99).round(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
        active_rules_count: state.engine.get_rules().len(),
        hot_compiled_rules_count: state.engine.dynamic_clauses_count(),
        pending_anomalies: pending,
    };

    Json(metrics)
}

async fn get_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let rules = state.engine.get_rules();
    Json(serde_json::json!({
        "status": "ok",
        "count": rules.len(),
        "rules": rules
    }))
}

async fn get_islands(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let islands = state.engine.get_islands();
    Json(serde_json::json!({
        "status": "ok",
        "count": islands.len(),
        "islands": islands
    }))
}

async fn get_islands_config(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let cfg = state.engine.islands_config.read().unwrap().clone();
    Json(serde_json::json!({
        "status": "ok",
        "islands": cfg
    }))
}

async fn update_islands_config(
    State(state): State<Arc<ProxyState>>,
    Json(cfg): Json<IslandsConfig>,
) -> impl IntoResponse {
    {
        let mut cur = state.engine.islands_config.write().unwrap();
        *cur = cfg.clone();
    }
    info!(target: "satguardian::api", "Updated islands config: wordpress={}, exposure={}, framework={}",
        cfg.wordpress_shield, cfg.exposure_shield, cfg.framework_shield);
    Json(serde_json::json!({
        "status": "ok",
        "message": "Protection islands updated successfully",
        "islands": cfg
    }))
}

async fn get_customer_rules(State(state): State<Arc<ProxyState>>) -> impl IntoResponse {
    let rules = state.engine.get_customer_business_rules();
    Json(serde_json::json!({
        "status": "ok",
        "count": rules.len(),
        "rules": rules
    }))
}

async fn add_customer_rule(
    State(state): State<Arc<ProxyState>>,
    Json(rule): Json<CustomBusinessRule>,
) -> impl IntoResponse {
    info!(target: "satguardian::api", "Adding/updating customer business rule: {} (id: {})", rule.name, rule.id);
    state.engine.add_customer_business_rule(rule.clone());
    Json(serde_json::json!({
        "status": "ok",
        "message": "Customer business rule added/updated successfully",
        "rule": rule
    }))
}

async fn delete_customer_rule(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let removed = state.engine.remove_customer_business_rule(&id);
    if removed {
        info!(target: "satguardian::api", "Removed customer business rule id: {}", id);
        Json(serde_json::json!({
            "status": "ok",
            "message": format!("Rule '{}' removed successfully", id)
        }))
    } else {
        Json(serde_json::json!({
            "status": "not_found",
            "message": format!("Rule '{}' not found", id)
        }))
    }
}

/// Requests cloud review of the recorded anomalies and stores the result as proposals.
async fn trigger_sync_simplify(State(state): State<Arc<ProxyState>>) -> Response {
    info!(target: "satguardian::sync", "Received request to synchronize novel anomalies with https://satguardian.tech");

    let pending_minterms = match state.ledger.get_pending_anomalies(100).await {
        Ok(m) => m,
        Err(e) => {
            error!(target: "satguardian::sync", "Failed to fetch pending anomalies: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)).into_response();
        }
    };

    if pending_minterms.is_empty() {
        return Json(serde_json::json!({
            "status": "noop",
            "message": "No pending novel anomalies in SQLite WAL ledger to simplify."
        }))
        .into_response();
    }

    let variables = FeatureBinarizer::get_variable_catalog(40);
    let req = SimplifyRequest {
        variables: variables.clone(),
        minterms: pending_minterms.clone(),
        dont_cares: None,
        format: Some("equation".to_string()),
    };

    match state.cloud_client.simplify(&req).await {
        Ok(resp) => {
            let clauses = match state
                .cloud_client
                .compile_equation_to_clauses(&resp.result, &variables)
            {
                Ok(clauses) if !clauses.is_empty() => clauses,
                Ok(_) => {
                    error!(
                        target: "satguardian::sync",
                        equation = %resp.result,
                        "Cloud returned an equation with no usable clauses; ledger left unchanged"
                    );
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({
                            "status": "rejected",
                            "error": "cloud_returned_no_usable_clauses",
                            "minimized_equation": resp.result
                        })),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!(
                        target: "satguardian::sync",
                        equation = %resp.result,
                        error = %e,
                        "Cloud returned an invalid equation; refusing to hot-load clauses"
                    );
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({
                            "status": "rejected",
                            "error": "invalid_cloud_equation",
                            "details": e,
                            "minimized_equation": resp.result
                        })),
                    )
                        .into_response();
                }
            };

            let mut proposed = Vec::new();
            let mut duplicates = 0usize;
            for clause in clauses {
                match state.ledger.propose_dynamic_clause(&clause).await {
                    Ok(true) => proposed.push(serde_json::json!({
                        "clause_id": clause.clause_id,
                        "description": clause.description,
                        "category": clause.category.as_str(),
                    })),
                    Ok(false) => duplicates += 1,
                    Err(e) => {
                        error!(target: "satguardian::ledger", "Failed to store proposed dynamic clause: {}", e);
                        duplicates += 1;
                    }
                }
            }

            if let Err(e) = state
                .ledger
                .record_simplification(&resp, variables.len(), pending_minterms.len())
                .await
            {
                error!(target: "satguardian::ledger", "Failed to record simplification history: {}", e);
            }
            if let Err(e) = state
                .ledger
                .mark_anomalies_simplified(&pending_minterms)
                .await
            {
                error!(target: "satguardian::ledger", "Failed to mark anomalies as simplified: {}", e);
            }

            info!(
                target: "satguardian::sync",
                reduction = %format!("{:.1}%", resp.reduction_percent),
                proposals = proposed.len(),
                duplicates,
                "Cloud review complete. Clauses stored as proposals; the running rule set is unchanged."
            );

            Json(serde_json::json!({
                "status": "proposed",
                "message": "Cloud synthesis returned update proposals. Nothing was applied to the running rule set; approve each one with POST /api/waf/clauses/{clause_id}/apply.",
                "minterms_processed": pending_minterms.len(),
                "variables_count": variables.len(),
                "reduction_percent": resp.reduction_percent,
                "minimized_equation": resp.result,
                "execution_time_ms": resp.execution_time_ms,
                "proposals": proposed,
                "duplicate_clauses_skipped": duplicates,
                "su_used": resp.su_used
            }))
            .into_response()
        }
        Err(err) => {
            error!(target: "satguardian::sync", "SATGuardian Cloud simplification error: {}", err);
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed to reach SATGuardian Cloud at https://satguardian.tech: {}", err),
            )
                .into_response()
        }
    }
}

/// Lists the cloud-synthesized clauses waiting for a decision.
async fn get_pending_clauses(State(state): State<Arc<ProxyState>>) -> Response {
    match state.ledger.load_pending_clauses().await {
        Ok(pending) => Json(serde_json::json!({
            "count": pending.len(),
            "proposals": pending
                .iter()
                .map(|(clause, created_at)| serde_json::json!({
                    "clause_id": clause.clause_id,
                    "description": clause.description,
                    "category": clause.category.as_str(),
                    "required_mask": clause.required_mask.to_string(),
                    "expected_bits": clause.expected_bits.to_string(),
                    "proposed_at": created_at,
                }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => {
            error!(target: "satguardian::ledger", "Failed to read pending clauses: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)).into_response()
        }
    }
}

/// The approval step: registers one proposal in the running engine and marks it applied.
async fn apply_pending_clause(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> Response {
    match state.ledger.approve_dynamic_clause(&id).await {
        Ok(Some(clause)) => {
            let enforcing = state.engine.register_dynamic_clause(clause.clone());
            info!(
                target: "satguardian::sync",
                clause_id = %id,
                enforcing,
                "Proposal approved by operator"
            );
            Json(serde_json::json!({
                "status": "approved",
                "clause_id": id,
                "description": clause.description,
                "enforcing_now": enforcing,
                "note": if enforcing {
                    "Clause is active for new requests."
                } else {
                    "Clause is saved and will load on restart; it duplicates an active rule or the clause cap was reached."
                }
            }))
            .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "no_pending_proposal",
                "clause_id": id,
                "hint": "GET /api/waf/clauses/pending lists the proposals waiting for a decision."
            })),
        )
            .into_response(),
        Err(e) => {
            error!(target: "satguardian::ledger", "Failed to approve clause {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)).into_response()
        }
    }
}

/// Discards a proposal. Rules already enforcing are never removed by this endpoint.
async fn reject_pending_clause(
    State(state): State<Arc<ProxyState>>,
    Path(id): Path<String>,
) -> Response {
    match state.ledger.reject_dynamic_clause(&id).await {
        Ok(true) => {
            info!(target: "satguardian::sync", clause_id = %id, "Proposal rejected by operator");
            Json(serde_json::json!({ "status": "rejected", "clause_id": id })).into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "no_pending_proposal",
                "clause_id": id,
                "note": "Only proposals awaiting a decision can be rejected; active rules are not deleted here."
            })),
        )
            .into_response(),
        Err(e) => {
            error!(target: "satguardian::ledger", "Failed to reject clause {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {}", e)).into_response()
        }
    }
}
