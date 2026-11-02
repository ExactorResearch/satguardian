use crate::engine::DynamicCompiledClause;
use crate::types::AttackCategory;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info};

/// Request format matching SATGuardian / EXACTOR GXOR Cloud Optimization API endpoint: `POST /api/simplify`.
/// Simplifies up to 128 Boolean variables (`u128` minterms) using the `{AND, OR, NOT, XOR}` operator basis.
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
        let url = if self.api_url.ends_with("/api/simplify") || self.api_url.ends_with("/simplify") {
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

        let resp = self
            .client
            .post(&url)
            .headers(headers)
            .json(request)
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
        let parsed: SimplifyResponse = serde_json::from_str(&body_text)
            .map_err(|e| format!("Failed to parse SimplifyResponse: {}. Raw: {}", e, body_text))?;

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
    /// The parser is intentionally strict: every literal must be an exact variable
    /// name, and unsupported syntax is rejected instead of being silently dropped.
    pub fn compile_equation_to_clauses(
        &self,
        equation: &str,
        variable_names: &[String],
    ) -> Result<Vec<DynamicCompiledClause>, String> {
        const MAX_TERMS: usize = 4096;

        let mut clauses = Vec::new();
        let equation = equation.trim();
        if equation.is_empty()
            || equation.eq_ignore_ascii_case("FALSE")
            || equation == "0"
        {
            return Ok(clauses);
        }
        if equation.eq_ignore_ascii_case("TRUE") || equation == "1" {
            return Err("equation TRUE would match every request; refusing to compile".to_string());
        }

        // Each term separated by '+' or '|' represents an OR prime implicant.
        for raw_term in equation.split(['+', '|', '∨']) {
            if clauses.len() >= MAX_TERMS {
                return Err(format!("equation exceeds the {} term limit", MAX_TERMS));
            }

            let term = raw_term
                .trim()
                .trim_matches(|c| c == '(' || c == ')')
                .trim();
            if term.is_empty() || term.eq_ignore_ascii_case("FALSE") || term == "0" {
                continue;
            }
            if term.eq_ignore_ascii_case("TRUE") || term == "1" {
                return Err(format!(
                    "term '{}' would match every request; refusing to compile",
                    term
                ));
            }
            if term.contains('(') || term.contains(')') {
                return Err(format!(
                    "nested parentheses are not supported in term '{}'",
                    term
                ));
            }
            if term.contains('^') {
                return Err(format!("XOR is not supported in term '{}'", term));
            }

            let normalized = term.replace(['∧', '&', '*', '·'], " ");
            let mut required_mask: u128 = 0;
            let mut expected_bits: u128 = 0;
            let mut seen: Vec<(usize, bool)> = Vec::new();
            let mut literal_count = 0usize;

            for literal in normalized.split_whitespace() {
                let literal = literal.trim_matches(|c| c == '(' || c == ')');
                if literal.is_empty() {
                    continue;
                }

                let (raw_name, negated) = if let Some(rest) = literal.strip_prefix('!') {
                    (rest, true)
                } else if let Some(rest) = literal.strip_prefix('~') {
                    (rest, true)
                } else if let Some(rest) = literal.strip_prefix('¬') {
                    (rest, true)
                } else if let Some(rest) = literal.strip_suffix('\'') {
                    (rest, true)
                } else {
                    (literal, false)
                };

                let name = raw_name.trim_matches(|c| c == '(' || c == ')');
                if name.is_empty() {
                    return Err(format!("malformed literal '{}' in term '{}'", literal, term));
                }

                let var_idx = variable_names
                    .iter()
                    .position(|candidate| candidate == name)
                    .ok_or_else(|| {
                        format!("unknown variable '{}' in term '{}'", name, term)
                    })?;
                if var_idx >= 128 {
                    return Err(format!(
                        "variable '{}' exceeds the 128-bit feature space",
                        name
                    ));
                }

                if let Some((_, previous_negation)) =
                    seen.iter().find(|(index, _)| *index == var_idx)
                {
                    if *previous_negation != negated {
                        return Err(format!(
                            "contradictory literal '{}' in term '{}'",
                            name, term
                        ));
                    }
                } else {
                    seen.push((var_idx, negated));
                }

                let bit = 1u128 << var_idx;
                required_mask |= bit;
                if !negated {
                    expected_bits |= bit;
                }
                literal_count += 1;
            }

            if literal_count == 0 || required_mask == 0 {
                return Err(format!("term '{}' contains no known literals", term));
            }

            clauses.push(DynamicCompiledClause {
                clause_id: format!(
                    "SAT-OPT-{:032x}-{:032x}",
                    required_mask, expected_bits
                ),
                description: format!("Dynamically minimized invariant term: {}", term),
                required_mask,
                expected_bits,
                category: AttackCategory::Unknown,
            });
        }

        Ok(clauses)
    }
}
