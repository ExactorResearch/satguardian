use satguardian_waf::engine::sat_solver::SatguardianSatEngine;
use satguardian_waf::stateful::limiter::{StatefulConfig, StatefulRateLimiter};
use satguardian_waf::types::{AttackCategory, AttackDecision, HttpRequestPayload};

#[test]
fn test_unicode_homoglyph_path_traversal() {
    let engine = SatguardianSatEngine::new();

    // Fullwidth slash '／' (U+FF0F) used to bypass traditional ASCII regex
    let payload = HttpRequestPayload::new("GET", "/images/..／..／etc／passwd", "", "");
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Homoglyph path traversal must be detected as violation");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PathTraversal);
}

#[test]
fn test_unicode_escape_sqli() {
    let engine = SatguardianSatEngine::new();

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
    let engine = SatguardianSatEngine::new();

    // %252e%252e%252f -> %2e%2e%2f -> ../
    let payload = HttpRequestPayload::new("GET", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", "", "");
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "Double URL encoded path traversal must be unmasked");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::PathTraversal);
}

#[test]
fn test_polyglot_payload_blocked() {
    let engine = SatguardianSatEngine::new();

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
    let engine = SatguardianSatEngine::new();

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

#[test]
fn test_ssrf_docker_gateway_and_decimal_and_ipv6() {
    let engine = SatguardianSatEngine::new();

    // 1. Docker host gateway (172.17.0.1 - RFC1918 Class B)
    let p_docker = HttpRequestPayload::new("GET", "/fetch?url=http://172.17.0.1:8080/internal", "", "");
    let proof_docker = engine.evaluate_payload(&p_docker);
    assert!(proof_docker.is_violation, "SSRF targeting Docker gateway 172.17.0.1 must be blocked");
    assert_eq!(proof_docker.category, AttackCategory::Ssrf);

    // 2. Decimal IP notation (2130706433 == 127.0.0.1)
    let p_dec = HttpRequestPayload::new("GET", "/proxy?target=http://2130706433/", "", "");
    let proof_dec = engine.evaluate_payload(&p_dec);
    assert!(proof_dec.is_violation, "SSRF with decimal IP 2130706433 must be blocked");
    assert_eq!(proof_dec.category, AttackCategory::Ssrf);

    // 3. IPv6 loopback [::1]
    let p_ipv6 = HttpRequestPayload::new("GET", "/proxy?target=http://[::1]/metrics", "", "");
    let proof_ipv6 = engine.evaluate_payload(&p_ipv6);
    assert!(proof_ipv6.is_violation, "SSRF with IPv6 loopback must be blocked");
    assert_eq!(proof_ipv6.category, AttackCategory::Ssrf);
}

#[test]
fn test_rce_newline_separator() {
    let engine = SatguardianSatEngine::new();

    // RCE using newline %0A as shell command separator
    let payload = HttpRequestPayload::new("POST", "/api/ping", "", "target=127.0.0.1%0awhoami");
    let proof = engine.evaluate_payload(&payload);

    assert!(proof.is_violation, "RCE using newline %0A delimiter must be blocked");
    assert_eq!(proof.action, AttackDecision::Block);
    assert_eq!(proof.category, AttackCategory::CommandInjection);
}

#[test]
fn test_sqli_parenthesis_union_and_tautology() {
    let engine = SatguardianSatEngine::new();

    // 1. UNION without whitespace using parentheses: UNION(SELECT...)
    let p_union = HttpRequestPayload::new("GET", "/items", "cat=1' UNION(SELECT 1,username,password FROM users)--", "");
    let proof_union = engine.evaluate_payload(&p_union);
    assert!(proof_union.is_violation, "SQLi UNION(SELECT...) without whitespace must be blocked");
    assert_eq!(proof_union.category, AttackCategory::SqlInjection);

    // 2. Tautology without whitespace: OR(1=1)
    let p_taut = HttpRequestPayload::new("GET", "/items", "id=1' OR(1=1)--", "");
    let proof_taut = engine.evaluate_payload(&p_taut);
    assert!(proof_taut.is_violation, "SQLi OR(1=1) without whitespace must be blocked");
    assert_eq!(proof_taut.category, AttackCategory::SqlInjection);
}

#[test]
fn test_uppercase_unicode_and_hex_dot_decode() {
    let engine = SatguardianSatEngine::new();

    // Uppercase hex/unicode escape with dots \u002E\u002E\u002F
    let payload = HttpRequestPayload::new(
        "GET",
        "/read?file=\\u002E\\u002E\\u002F\\u002E\\u002E\\u002Fetc\\u002Fpasswd",
        "",
        "",
    );
    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation, "Uppercase Unicode escaped dot-dot-slash must be unmasked");
    assert_eq!(proof.category, AttackCategory::PathTraversal);
}

#[test]
fn test_prototype_pollution_in_query_params() {
    let engine = SatguardianSatEngine::new();

    // Prototype pollution in query parameter instead of root JSON body
    let payload = HttpRequestPayload::new("GET", "/api/users", "__proto__[role]=admin", "");
    let proof = engine.evaluate_payload(&payload);
    assert!(proof.is_violation, "Prototype pollution in query parameter must be blocked");
    assert_eq!(proof.category, AttackCategory::PrototypePollution);
}

#[test]
fn test_legitimate_index_php_allowed_with_wordpress_shield() {
    use satguardian_waf::config::{BusinessRulesConfig, IslandsConfig};

    // For applications legitimately running PHP or WordPress, wordpress_shield is set to false
    let islands = IslandsConfig {
        wordpress_shield: false,
        exposure_shield: true,
        framework_shield: true,
    };
    let engine = SatguardianSatEngine::with_config(islands, BusinessRulesConfig::default());

    // Legitimate framework request to index.php with controller parameters
    let payload = HttpRequestPayload::new("GET", "/index.php", "controller=catalog&action=detail&id=42", "");
    let proof = engine.evaluate_payload(&payload);
    assert!(!proof.is_violation, "Legitimate PHP index.php route must NOT be blocked when wordpress_shield is false");
}
