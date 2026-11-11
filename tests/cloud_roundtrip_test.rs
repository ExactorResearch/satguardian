//! End-to-end round-trip against the live SATGuardian cloud synthesis service.
//!
//! Verifies the two properties the edge depends on:
//!   1. `simplify()` submits variables in the order the service expects, so the
//!      returned equation's variable names line up with feature-bit positions.
//!   2. `compile_equation_to_clauses()` can compile equations that contain XOR
//!      factors — the shape the minimizer actually returns.
//!
//! The test asserts the compiled clauses reproduce the submitted minterm
//! on-set exactly. It is skipped unless `SATGUARDIAN_API_KEY` is set, because
//! it spends Security Units on every run.
//!
//! ```powershell
//! $env:SATGUARDIAN_API_KEY="ek_..."; cargo test --release --test cloud_roundtrip_test -- --nocapture
//! ```

use satguardian_waf::ast::features::FeatureBinarizer;
use satguardian_waf::cloud::{SatguardianCloudClient, SimplifyRequest};

#[tokio::test]
async fn cloud_equation_round_trips_to_bitmask_clauses() {
    let api_key = match std::env::var("SATGUARDIAN_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!("SATGUARDIAN_API_KEY not set; skipping live cloud round-trip");
            return;
        }
    };
    let api_url = std::env::var("SATGUARDIAN_API_URL")
        .unwrap_or_else(|_| "https://satguardian.tech/api/simplify".to_string());

    // Small variable count keeps the brute-force check exhaustive (2^8).
    let names: Vec<String> = FeatureBinarizer::get_variable_catalog(8);
    let n = names.len();
    let minterms: Vec<u128> = vec![0b0000_0101, 0b0010_1100, 0b1000_0011, 0b0110_0110];

    let client = SatguardianCloudClient::new(api_url, Some(api_key));
    let resp = client
        .simplify(&SimplifyRequest {
            variables: names.clone(),
            minterms: minterms.clone(),
            dont_cares: None,
            format: Some("equation".to_string()),
        })
        .await
        .expect("simplify call failed");

    eprintln!("equation: {}", resp.result);
    eprintln!("su_used: {:?}", resp.su_used);

    let clauses = client
        .compile_equation_to_clauses(&resp.result, &names)
        .expect("returned equation could not be compiled to clauses");
    assert!(!clauses.is_empty(), "no clauses compiled from equation");

    // The compiled clauses must reproduce exactly the submitted on-set.
    let mut on_set = vec![false; 1usize << n];
    for m in 0..(1u128 << n) {
        for c in &clauses {
            if (m & c.required_mask) == c.expected_bits {
                on_set[m as usize] = true;
                break;
            }
        }
    }
    for &mt in &minterms {
        assert!(on_set[mt as usize], "minterm {} not covered by clauses", mt);
    }
    for m in 0..(1u128 << n) {
        if !minterms.contains(&m) {
            assert!(
                !on_set[m as usize],
                "off-set minterm {} covered by clauses",
                m
            );
        }
    }
}
