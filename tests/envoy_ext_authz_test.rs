use satguardian_waf::config::WafConfig;
use satguardian_waf::engine::SatguardianSatEngine;
use satguardian_waf::envoy::{create_envoy_authz_router, EnvoyAuthzState};
use satguardian_waf::ledger::SqliteLedger;
use satguardian_waf::stateful::StatefulRateLimiter;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

async fn setup_test_router(db_path: &str) -> axum::Router {
    let ledger = SqliteLedger::init(db_path).await.expect("Failed to init test db");
    let config = WafConfig::default();
    let stateful_limiter = Arc::new(StatefulRateLimiter::new(config.to_stateful_config()));
    let engine = Arc::new(SatguardianSatEngine::new());

    let state = EnvoyAuthzState::new(
        engine,
        ledger,
        stateful_limiter,
        "block".to_string(),
    );

    create_envoy_authz_router(state)
}

#[tokio::test]
async fn test_envoy_ext_authz_benign_request_allowed() {
    let db_path = format!("target/test_envoy_{}.db", &uuid::Uuid::new_v4().to_string()[..8]);
    let app = setup_test_router(&db_path).await;

    let req = Request::builder()
        .method("GET")
        .uri("/ext_authz")
        .header("x-envoy-original-path", "/api/v1/products?page=2")
        .header("x-envoy-original-method", "GET")
        .header("x-forwarded-for", "192.168.1.100")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-envoy-waf-verified").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-satguardian-verified").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-exactor-verified").unwrap(),
        "true"
    );
    assert!(response.headers().contains_key("x-envoy-waf-latency-us"));
    assert!(response.headers().contains_key("x-satguardian-latency-us"));
    assert!(response.headers().contains_key("x-exactor-latency-us"));
}

#[tokio::test]
async fn test_envoy_ext_authz_sqli_blocked_with_proof() {
    let db_path = format!("target/test_envoy_{}.db", &uuid::Uuid::new_v4().to_string()[..8]);
    let app = setup_test_router(&db_path).await;

    let req = Request::builder()
        .method("GET")
        .uri("/ext_authz")
        .header("x-envoy-original-path", "/search?q=admin'%20OR%201=1--")
        .header("x-envoy-original-method", "GET")
        .header("x-forwarded-for", "203.0.113.42")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get("x-envoy-waf-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-satguardian-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-exactor-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-envoy-waf-category").unwrap(),
        "sql_injection"
    );
    assert_eq!(
        response.headers().get("x-satguardian-category").unwrap(),
        "sql_injection"
    );
    assert_eq!(
        response.headers().get("x-exactor-category").unwrap(),
        "sql_injection"
    );
}

#[tokio::test]
async fn test_envoy_ext_authz_post_body_xss_blocked() {
    let db_path = format!("target/test_envoy_{}.db", &uuid::Uuid::new_v4().to_string()[..8]);
    let app = setup_test_router(&db_path).await;

    let xss_body = "{\"comment\": \"<script>alert('XSS')</script>\"}";

    let req = Request::builder()
        .method("POST")
        .uri("/ext_authz")
        .header("x-envoy-original-path", "/api/v1/comments")
        .header("x-envoy-original-method", "POST")
        .header("content-type", "application/json")
        .header("x-forwarded-for", "198.51.100.22")
        .body(Body::from(xss_body))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get("x-envoy-waf-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-satguardian-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-exactor-blocked").unwrap(),
        "true"
    );
    assert_eq!(
        response.headers().get("x-envoy-waf-category").unwrap(),
        "xss"
    );
    assert_eq!(
        response.headers().get("x-satguardian-category").unwrap(),
        "xss"
    );
    assert_eq!(
        response.headers().get("x-exactor-category").unwrap(),
        "xss"
    );
}
