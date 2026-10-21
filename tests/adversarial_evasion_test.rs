use exactor_waf_guardian::engine::sat_solver::ExactorSatEngine;
use exactor_waf_guardian::stateful::limiter::{StatefulConfig, StatefulRateLimiter};
use exactor_waf_guardian::types::{AttackCategory, AttackDecision, HttpRequestPayload};

#[test]
fn test_unicode_homoglyph_path_traversal() {
    let engine = ExactorSatEngine::new();

    // Fullwidth slash '／' (U+FF0F) used to bypass traditional ASCII regex
    let payload = HttpRequestPayload::new("GET", "/images/..／..／etc／passwd", "", "");
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Homoglyph path traversal must be detected as violation");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PathTraversal);
}

#[test]
fn test_unicode_escape_sqli() {
    let engine = ExactorSatEngine::new();

    // JSON body with Unicode escaped quote (\u0027) designed to bypass naive quote checks
    let payload = HttpRequestPayload::new(
        "POST",
        "/api/login",
        "",
        r#"{"username": "\u0027 OR 1=1--", "password": "password"}"#,
    );
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Unicode escaped SQLi quote must be unmasked and blocked");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::SqlInjection);
}

#[test]
fn test_double_url_encoded_traversal() {
    let engine = ExactorSatEngine::new();

    // %252e%252e%252f -> %2e%2e%2f -> ../
    let payload = HttpRequestPayload::new("GET", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "", "");
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Double URL encoded path traversal must be unmasked");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PathTraversal);
}

#[test]
fn test_polyglot_payload_blocked() {
    let engine = ExactorSatEngine::new();

    // Polyglot combining SQLi, XSS, and Shell Metachars
    let payload = HttpRequestPayload::new(
        "POST",
        "/comment",
        "",
        "title=1' UNION SELECT 1, '<script>alert(1)</script>'-- &body=;cat /etc/passwd",
    );
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Adversarial polyglot payload must be blocked");
    assert_eq!(proof.action, AttackDecision::Block);
    assert!(!proof.matched_rules.is_empty(), "Must match one or more formal invariant rules");
}

#[test]
fn test_stateful_ip_flooding_memory_bounded() {
    // Configure rate limiter with strict memory bound of 200 clients
    let config = StatefulConfig {
        enabled: true,
        window_secs: 60,
        num_buckets: 12,
        global_limit_per_window: 100,
        auth_limit_per_window: 10,
        ban_duration_secs: 60,
        max_tracked_clients: 200, // Small ceiling to stress eviction
        redis_url: None,
    };
    let limiter = StatefulRateLimiter::new(config);

    // Simulate adversarial IP flood with 1,500 distinct spoofed IPs
    for i in 0..1500 {
        let fake_ip = format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF);
        let req = HttpRequestPayload::with_ip("GET", "/public-feed", "", "", &fake_ip);
        limiter.check_and_update(&req);
    }

    let tracked = limiter.tracked_clients_count();
    assert!(
        tracked <= 200,
        "Tracked clients count ({}) must NOT exceed max_tracked_clients (200) under IP flood DoS",
        tracked
    );
}

#[test]
fn test_massive_payload_bomb_fast_fails() {
    let engine = ExactorSatEngine::new();

    // Generate a 1.5 MB payload bomb
    let massive_body = "A".repeat(1_500_000);
    let payload = HttpRequestPayload::new("POST", "/upload", "", &massive_body);

    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation);
    assert_eq!(proof.action, AttackDecision::Block);
    assert!(
        proof.execution_time_us < 1000.0,
        "Massive payload bomb must fast-fail in < 1ms (took {}µs)",
        proof.execution_time_us
    );
}
