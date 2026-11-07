use crate::engine::DynamicCompiledClause;
use crate::types::AttackCategory;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info};

/// Request format for the SATGuardian cloud synthesis endpoint: `POST /api/simplify`.
/// The minimization itself runs server-side; the client only sends minterms and evaluates what
/// comes back after an operator approves it. Up to 128 variables (`u128` minterms).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SimplifyRequest {
    pub variables: Vec<String>,
    pub minterms: Vec<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dont_cares: Option<Vec<u128>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Response returned by https://satguardian.tech/api/simplify.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SimplifyResponse {
    pub result: String,
    pub variable_count: usize,
    pub reduction_percent: f64,
    pub original_gates: usize,
    pub new_gates: usize,
    pub execution_time_ms: u64,
    pub espresso: Option<String>,
    pub verilog: Option<String>,
    pub vhdl: Option<String>,
    pub blif: Option<String>,
    pub su_used: Option<i64>,
}

/// Entitlement response from GET /api/edge/entitlement.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EdgeEntitlementResponse {
    pub edge_traffic_unlimited: bool,
    pub cloud_synthesis_enabled: bool,
    pub subscription_tier: String,
    pub su_available: i64,
    pub su_expires_at: Option<String>,
    pub included_su_month: i64,
    pub overage_usd_per_1k_su: Option<f64>,
    pub max_variables: usize,
    pub max_minterms: Option<usize>,
    pub explanation: Option<String>,
}

/// Number of feature variables submitted to cloud synthesis. The PRO plan
/// ceiling is 64 variables; the edge feature catalogue is wider, so the tail
/// is truncated server-side and simply never participates in learned clauses.
pub const CLOUD_SYNC_VARIABLE_COUNT: usize = 64;

/// High-performance HTTP client for the SATGuardian Cloud Optimization Engine.
#[derive(Clone)]
pub struct SatguardianCloudClient {
    client: Client,
    api_url: String,
    api_token: Option<String>,
}

/// Backward compatibility alias for SATGuardian Cloud Client.
pub type ExactorCloudClient = SatguardianCloudClient;

impl SatguardianCloudClient {
    pub fn new(api_url: impl Into<String>, api_token: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to initialize reqwest client");

        Self {
            client,
            api_url: api_url.into(),
            api_token,
        }
    }

    /// Query the cloud entitlement and Security Units (SU) balance from /api/edge/entitlement.
    pub async fn get_entitlement(
        &self,
    ) -> Result<EdgeEntitlementResponse, Box<dyn std::error::Error + Send + Sync>> {
        let base_url = if self.api_url.ends_with("/api/simplify") {
            self.api_url.trim_end_matches("/api/simplify")
        } else if self.api_url.ends_with("/simplify") {
            self.api_url.trim_end_matches("/simplify")
        } else {
            self.api_url.trim_end_matches('/')
        };
        let url = format!("{}/api/edge/entitlement", base_url);

        let mut req = self.client.get(&url);
        if let Some(token) = &self.api_token {
            let auth_str = if token.starts_with("Bearer ") || token.starts_with("ApiKey ") {
                token.clone()
            } else {
                format!("Bearer {}", token)
            };
            req = req.header(AUTHORIZATION, auth_str);
        }

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let err_text = resp.text().await.unwrap_or_default();
            return Err(format!("Entitlement check failed (HTTP {}): {}", status, err_text).into());
        }
        let ent: EdgeEntitlementResponse = resp.json().await?;
        Ok(ent)
    }

    /// Primary invocation to https://satguardian.tech/api/simplify.
    pub async fn simplify(
        &self,
        request: &SimplifyRequest,
    ) -> Result<SimplifyResponse, Box<dyn std::error::Error + Send + Sync>> {
        let url = if self.api_url.ends_with("/api/simplify") || self.api_url.ends_with("/simplify")
        {
            self.api_url.clone()
        } else {
            format!("{}/api/simplify", self.api_url.trim_end_matches('/'))
        };

        info!(
            target: "satguardian::cloud",
            url = %url,
            vars = request.variables.len(),
            minterms = request.minterms.len(),
            "Invoking SATGuardian Boolean simplification API at https://satguardian.tech"
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            HeaderName::from_static("x-satguardian-programmatic"),
            HeaderValue::from_static("true"),
        );

        if let Some(token) = &self.api_token {
            let auth_str = if token.starts_with("Bearer ") || token.starts_with("ApiKey ") {
                token.clone()
            } else {
                format!("Bearer {}", token)
            };
            if let Ok(val) = HeaderValue::from_str(&auth_str) {
                headers.insert(AUTHORIZATION, val);
            }
        }

        // The service maps submitted minterm bit `i` onto `variables[n - 1 - i]`
        // (verified against the live API on 2026-11-07). The edge engine numbers
        // feature bits so that bit `i` is `variables[i]`, so the variable list
        // is reversed on the wire to keep name -> bit alignment intact.
        let mut wire_request = request.clone();
        wire_request.variables.reverse();

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .json(&wire_request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            error!(
                target: "satguardian::cloud",
                status = %status,
                body = %err_text,
                "SATGuardian cloud simplification failed"
            );
            return Err(format!("SATGuardian API returned error {}: {}", status, err_text).into());
        }

        let body_text = resp.text().await?;
        let parsed: SimplifyResponse = serde_json::from_str(&body_text).map_err(|e| {
            format!(
                "Failed to parse SimplifyResponse: {}. Raw: {}",
                e, body_text
            )
        })?;

        info!(
            target: "satguardian::cloud",
            reduction = %format!("{:.1}%", parsed.reduction_percent),
            original_gates = parsed.original_gates,
            new_gates = parsed.new_gates,
            exec_ms = parsed.execution_time_ms,
            su_used = ?parsed.su_used,
            "Successfully received minimized Boolean function from SATGuardian Cloud"
        );

        Ok(parsed)
    }

    /// Compiles the returned boolean formula into runtime bitmask invariants.
    ///
    /// The service emits a sum-of-products equation whose product terms may
    /// contain XOR factors, e.g. `v0 !(v1 ^ v2) + (v3 ^ v4) !v5`. XOR factors
    /// are not cubes, so each term is expanded into the set of cubes it
    /// covers: a factor over `m` variables contributes `2^(m-1)` partial
    /// assignments, and the term's cubes are the consistent combinations of
    /// its factors. Expansion is bounded by [`MAX_TERMS`]; a formula that
    /// would exceed it is rejected rather than truncated, because a partial
    /// clause set would silently weaken the invariant.
    ///
    /// The parser is intentionally strict: every literal must be an exact
    /// variable name, and unsupported syntax is rejected instead of being
    /// silently dropped.
    pub fn compile_equation_to_clauses(
        &self,
        equation: &str,
        variable_names: &[String],
    ) -> Result<Vec<DynamicCompiledClause>, String> {
        const MAX_TERMS: usize = 4096;

        let name_to_idx: std::collections::HashMap<&str, usize> = variable_names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i))
            .collect();
        let lookup = |name: &str| -> Result<usize, String> {
            name_to_idx
                .get(name)
                .copied()
                .ok_or_else(|| format!("unknown variable '{}'", name))
        };

        let mut cubes: Vec<(u128, u128)> = Vec::new();
        for raw_term in split_equation_terms(equation) {
            let term = raw_term.trim();
            if term.is_empty() || term.eq_ignore_ascii_case("FALSE") || term == "0" {
                continue;
            }
            if term.eq_ignore_ascii_case("TRUE") || term == "1" {
                return Err(
                    "equation TRUE would match every request; refusing to compile".to_string(),
                );
            }

            // Each term is a conjunction of literals and XOR groups; expand it
            // into the cubes it covers.
            let mut term_cubes: Vec<(u128, u128)> = vec![(0, 0)];
            for factor in parse_term_factors(term, &lookup)? {
                let options = factor_options(&factor, MAX_TERMS)?;
                if options.is_empty() {
                    term_cubes.clear();
                    break;
                }
                if term_cubes.len().saturating_mul(options.len()) > MAX_TERMS {
                    return Err(format!(
                        "term expansion exceeds the {} clause limit",
                        MAX_TERMS
                    ));
                }
                let mut next = Vec::with_capacity(term_cubes.len() * options.len());
                for &(cm, cb) in &term_cubes {
                    for &(om, ob) in &options {
                        // Shared variables must agree on polarity.
                        if (cb ^ ob) & (cm & om) != 0 {
                            continue;
                        }
                        next.push((cm | om, cb | ob));
                    }
                }
                term_cubes = next;
            }

            if term_cubes.is_empty() {
                // Unsatisfiable term (e.g. `a !a`): contributes nothing.
                continue;
            }
            if cubes.len() + term_cubes.len() > MAX_TERMS {
                return Err(format!("equation exceeds the {} clause limit", MAX_TERMS));
            }
            cubes.extend(term_cubes);
        }

        cubes.sort_unstable();
        cubes.dedup();

        let mut clauses = Vec::with_capacity(cubes.len());
        for (required_mask, expected_bits) in cubes {
            if required_mask == 0 {
                return Err(
                    "equation contains a clause with no literals; refusing to compile".to_string(),
                );
            }
            clauses.push(DynamicCompiledClause {
                clause_id: format!("SAT-OPT-{:032x}-{:032x}", required_mask, expected_bits),
                description: format!(
                    "Dynamically minimized invariant term: mask {:032x} bits {:032x}",
                    required_mask, expected_bits
                ),
                required_mask,
                expected_bits,
                category: AttackCategory::Unknown,
            });
        }

        Ok(clauses)
    }
}

/// Maximum variables allowed inside one XOR factor. Each variable doubles the
/// number of cubes the factor expands to, so wide groups are rejected before
/// they can exhaust the clause budget.
const MAX_XOR_VARS: usize = 12;

/// Splits an equation into its top-level OR terms on `+`, `|` or `∨`,
/// ignoring separators nested inside parentheses.
fn split_equation_terms(equation: &str) -> Vec<String> {
    let mut terms = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in equation.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            '+' | '|' | '∨' if depth == 0 => {
                terms.push(std::mem::take(&mut current));
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    terms.push(current);
    terms
}

/// One conjunct inside a product term: either a literal or a parenthesized
/// XOR group, each optionally negated.
enum EquationFactor {
    Lit {
        idx: usize,
        negated: bool,
    },
    Xor {
        vars: Vec<(usize, bool)>,
        negated: bool,
    },
}

type NameLookup<'a> = dyn Fn(&str) -> Result<usize, String> + 'a;

/// Splits a product term into factors on whitespace that is not inside
/// parentheses, then parses each factor.
fn parse_term_factors(term: &str, lookup: &NameLookup) -> Result<Vec<EquationFactor>, String> {
    let mut raw = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in term.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_whitespace() && depth == 0 => {
                if !current.trim().is_empty() {
                    raw.push(std::mem::take(&mut current));
                }
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.trim().is_empty() {
        raw.push(current);
    }
    if depth != 0 {
        return Err(format!("unbalanced parentheses in term '{}'", term));
    }

    raw.iter().map(|t| parse_factor(t, lookup)).collect()
}

fn is_negation_char(ch: char) -> bool {
    matches!(ch, '!' | '~' | '¬')
}

fn is_factor_break(ch: char) -> bool {
    ch.is_whitespace()
        || is_negation_char(ch)
        || matches!(
            ch,
            '(' | ')' | '^' | '+' | '|' | '∨' | '*' | '·' | '&' | '∧'
        )
}

fn parse_factor(raw: &str, lookup: &NameLookup) -> Result<EquationFactor, String> {
    let mut s = raw.trim();
    let mut negated = false;
    while let Some(rest) = s.strip_prefix(is_negation_char) {
        negated = !negated;
        s = rest;
    }
    while let Some(rest) = s.strip_suffix('\'') {
        negated = !negated;
        s = rest.trim_end();
    }
    s = s.trim();
    if s.is_empty() {
        return Err(format!("empty literal in factor '{}'", raw));
    }

    if let Some(inner) = s.strip_prefix('(') {
        let inner = inner
            .strip_suffix(')')
            .ok_or_else(|| format!("unbalanced parentheses in factor '{}'", raw))?;
        let mut vars = Vec::new();
        for part in inner.split('^') {
            let mut p = part.trim();
            let mut inner_neg = false;
            while let Some(rest) = p.strip_prefix(is_negation_char) {
                inner_neg = !inner_neg;
                p = rest;
            }
            p = p.trim();
            if p.is_empty() || p.chars().any(is_factor_break) {
                return Err(format!(
                    "malformed XOR literal '{}' in factor '{}'",
                    part.trim(),
                    raw
                ));
            }
            vars.push((lookup(p)?, inner_neg));
        }
        if vars.is_empty() {
            return Err(format!("empty XOR group in factor '{}'", raw));
        }
        if vars.len() > MAX_XOR_VARS {
            return Err(format!(
                "XOR group with {} variables exceeds the {} variable limit",
                vars.len(),
                MAX_XOR_VARS
            ));
        }
        let mut seen = std::collections::HashSet::new();
        if vars.iter().any(|(idx, _)| !seen.insert(*idx)) {
            return Err(format!("duplicate variable inside XOR group '{}'", raw));
        }
        return Ok(EquationFactor::Xor { vars, negated });
    }

    if s.chars().any(is_factor_break) {
        return Err(format!("malformed literal '{}'", s));
    }
    Ok(EquationFactor::Lit {
        idx: lookup(s)?,
        negated,
    })
}

/// Expands one factor into the partial assignments `(mask, expected_bits)` it
/// covers. A literal fixes one bit; an XOR group over `m` variables fixes all
/// `m` bits and contributes `2^(m-1)` options.
fn factor_options(factor: &EquationFactor, max_terms: usize) -> Result<Vec<(u128, u128)>, String> {
    match factor {
        EquationFactor::Lit { idx, negated } => {
            if *idx >= 128 {
                return Err(format!(
                    "variable index {} exceeds the 128-bit feature space",
                    idx
                ));
            }
            let mask = 1u128 << idx;
            Ok(vec![(mask, if *negated { 0 } else { mask })])
        }
        EquationFactor::Xor { vars, negated } => {
            if vars.iter().any(|(idx, _)| *idx >= 128) {
                return Err("variable index exceeds the 128-bit feature space".to_string());
            }
            let m = vars.len();
            let space = 1usize << m;
            if space / 2 > max_terms {
                return Err(format!(
                    "XOR group over {} variables expands to {} clauses, over the {} limit",
                    m,
                    space / 2,
                    max_terms
                ));
            }
            let mut options = Vec::with_capacity(space / 2);
            for assignment in 0..space {
                // Literal values: variable bit XOR inner negation.
                let mut parity = 0u8;
                for (k, (_, inner_neg)) in vars.iter().enumerate() {
                    parity ^= (((assignment >> k) & 1) as u8) ^ (*inner_neg as u8);
                }
                // XOR of the literals, then the optional outer negation.
                let value = (parity & 1) ^ (*negated as u8);
                if value == 0 {
                    continue;
                }
                let mut mask = 0u128;
                let mut bits = 0u128;
                for (k, (idx, _)) in vars.iter().enumerate() {
                    mask |= 1u128 << idx;
                    if (assignment >> k) & 1 == 1 {
                        bits |= 1u128 << idx;
                    }
                }
                options.push((mask, bits));
            }
            Ok(options)
        }
    }
}
