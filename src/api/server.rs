use crate::ast::features::FeatureBinarizer;
use crate::cloud::SimplifyRequest;
use crate::config::{CustomBusinessRule, IslandsConfig};
use crate::proxy::ProxyState;
use crate::types::{HttpRequestPayload, ProofChain, WafMetricsSnapshot};
use axum::{
    extract::{Path, State},
    http::StatusCode,
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

pub fn create_api_router() -> Router<Arc<ProxyState>> {
    Router::new()
        .route("/health", get(health_check))
        .route("/livez", get(health_check))
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
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "exactor-waf-guardian",
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
    let sum_lat = state.sum_latency_us.load(Ordering::Relaxed);

    let avg_latency = if total > 0 {
        (sum_lat as f64) / (total as f64)
    } else {
        0.0
    };

    let pending = state.ledger.count_pending_anomalies().await;

    let metrics = WafMetricsSnapshot {
        total_requests: total,
        blocked_requests: blocked,
        allowed_requests: allowed,
        avg_latency_us: (avg_latency * 100.0).round() / 100.0,
        p99_latency_us: (avg_latency * 1.5).round(), // estimated p99
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

/// Triggers autonomous Exact Boolean Minimization using https://satguardian.tech/api/simplify.
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

    let variables = FeatureBinarizer::get_variable_catalog(24);
    let req = SimplifyRequest {
        variables: variables.clone(),
        minterms: pending_minterms.clone(),
        dont_cares: None,
        format: Some("equation".to_string()),
    };

    match state.cloud_client.simplify(&req).await {
        Ok(resp) => {
            let clauses = state.cloud_client.compile_equation_to_clauses(&resp.result, &variables);
            let clauses_count = clauses.len();

            for c in clauses {
                state.engine.register_dynamic_clause(c);
            }

            let _ = state.ledger.record_simplification(&resp, variables.len(), pending_minterms.len()).await;
            let _ = state.ledger.mark_anomalies_simplified(&pending_minterms).await;

            info!(
                target: "satguardian::sync",
                reduction = %format!("{:.1}%", resp.reduction_percent),
                hot_rules_added = clauses_count,
                "Hot minimization complete. Dynamic clauses registered into in-memory Fast-Path."
            );

            Json(serde_json::json!({
                "status": "success",
                "message": "Exact Boolean Simplification completed via https://satguardian.tech",
                "minterms_processed": pending_minterms.len(),
                "variables_count": variables.len(),
                "reduction_percent": resp.reduction_percent,
                "minimized_equation": resp.result,
                "execution_time_ms": resp.execution_time_ms,
                "dynamic_clauses_added": clauses_count,
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
