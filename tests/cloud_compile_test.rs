//! Tests for compiling SATGuardian cloud equations (which may contain XOR
//! factors) into runtime bitmask clauses.

use satguardian_waf::cloud::SatguardianCloudClient;

fn vars(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn client() -> SatguardianCloudClient {
    SatguardianCloudClient::new("http://127.0.0.1:1", None)
}

/// On-set of the compiled clauses over `n` variables, as minterm integers
/// where bit `i` is variable `i`.
fn on_set(clauses: &[(u128, u128)], n: usize) -> Vec<u128> {
    let mut out = Vec::new();
    'outer: for m in 0..(1u128 << n) {
        for &(mask, bits) in clauses {
            if (m & mask) == bits {
                out.push(m);
                continue 'outer;
            }
        }
    }
    out
}

fn compile(equation: &str, names: &[&str]) -> Vec<(u128, u128)> {
    let c = client();
    let clauses = c
        .compile_equation_to_clauses(equation, &vars(names))
        .unwrap_or_else(|e| panic!("equation {:?} rejected: {}", equation, e));
    clauses
        .iter()
        .map(|c| (c.required_mask, c.expected_bits))
        .collect()
}

#[test]
fn plain_literals_compile_to_single_cubes() {
    let names = vars(&["a", "b", "c"]);
    let c = client();
    let clauses = c.compile_equation_to_clauses("a !b + c", &names).unwrap();
    assert_eq!(clauses.len(), 2);
    assert_eq!(clauses[0].required_mask, 0b011);
    assert_eq!(clauses[0].expected_bits, 0b001);
    assert_eq!(clauses[1].required_mask, 0b100);
    assert_eq!(clauses[1].expected_bits, 0b100);
}

#[test]
fn xor_group_expands_to_parity_cubes() {
    // !(a ^ b) == (a & b) | (!a & !b)
    let clauses = compile("!(a ^ b)", &["a", "b"]);
    assert_eq!(clauses.len(), 2);
    let on = on_set(&clauses, 2);
    assert_eq!(on, vec![0b00, 0b11]);
}

#[test]
fn mixed_term_with_xor_and_literals() {
    // a !(b ^ c) + (a ^ b) !c  over {a,b,c}
    let clauses = compile("a !(b ^ c) + (a ^ b) !c", &["a", "b", "c"]);
    let on = on_set(&clauses, 3);
    // brute-force the intended function
    let mut expected = Vec::new();
    for m in 0..8u128 {
        let a = m & 1 != 0;
        let b = m & 2 != 0;
        let c = m & 4 != 0;
        if (a && !(b ^ c)) || ((a ^ b) && !c) {
            expected.push(m);
        }
    }
    assert_eq!(on, expected);
}

#[test]
fn real_service_equation_with_shared_xor_vars() {
    // Captured live from satguardian.tech /api/simplify on 2026-11-07.
    let clauses = compile(
        "!v0_quote !v1_tautology v2_union_select (v3_time_delay ^ v4_stacked_ddl) \
         v5_script_tag !(v6_event_handler ^ v4_stacked_ddl) !(v6_event_handler ^ v7_js_scheme) \
         + !v0_quote !v1_tautology v2_union_select",
        &[
            "v0_quote",
            "v1_tautology",
            "v2_union_select",
            "v3_time_delay",
            "v4_stacked_ddl",
            "v5_script_tag",
            "v6_event_handler",
            "v7_js_scheme",
        ],
    );
    // Just verify every clause is a valid cube over the 8 variables.
    for (mask, bits) in &clauses {
        assert_ne!(*mask, 0);
        assert_eq!(bits & !mask, 0, "expected bits outside mask");
    }
    assert!(!clauses.is_empty());
}

#[test]
fn unsatisfiable_term_contributes_nothing() {
    // `a !a` can never hold; only the second term survives.
    let clauses = compile("a !a + b", &["a", "b"]);
    assert_eq!(clauses.len(), 1);
    assert_eq!(on_set(&clauses, 2), vec![0b10, 0b11]);
}

#[test]
fn false_and_empty_equations_yield_no_clauses() {
    let c = client();
    let names = vars(&["a"]);
    assert!(c
        .compile_equation_to_clauses("FALSE", &names)
        .unwrap()
        .is_empty());
    assert!(c
        .compile_equation_to_clauses("", &names)
        .unwrap()
        .is_empty());
}

#[test]
fn tautology_and_unknown_variables_are_rejected() {
    let c = client();
    let names = vars(&["a", "b"]);
    assert!(c.compile_equation_to_clauses("TRUE", &names).is_err());
    assert!(c.compile_equation_to_clauses("a + TRUE", &names).is_err());
    assert!(c.compile_equation_to_clauses("a + zzz", &names).is_err());
    assert!(c.compile_equation_to_clauses("!(a ^ zzz)", &names).is_err());
}

#[test]
fn malformed_syntax_is_rejected() {
    let c = client();
    let names = vars(&["a", "b"]);
    assert!(c.compile_equation_to_clauses("(a ^ b", &names).is_err());
    assert!(c.compile_equation_to_clauses("a ^", &names).is_err());
    assert!(c.compile_equation_to_clauses("a $ b", &names).is_err());
}
