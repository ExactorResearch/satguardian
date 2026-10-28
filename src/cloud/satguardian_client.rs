use crate::engine::DynamicCompiledClause;
use crate::types::AttackCategory;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info};

/// Request format matching SATGuardian Cloud Optimization API endpoint: `POST /api/simplify`.
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

    /// Compiles the returned boolean formula / result into runtime bitmask invariants.
    pub fn compile_equation_to_clauses(
        &self,
        equation: &str,
        variable_names: &[String],
    ) -> Vec<DynamicCompiledClause> {
        let mut clauses = Vec::new();
        if equation.is_empty() || equation == "FALSE" {
            return clauses;
        }

        // Each term separated by '+' or '|' represents an OR prime implicant
        let terms = equation.split(['+', '|']);
        for (idx, term) in terms.enumerate() {
            let clean_term = term.trim();
            if clean_term.is_empty() || clean_term == "TRUE" {
                continue;
            }

            let mut required_mask: u128 = 0;
            let mut expected_bits: u128 = 0;

            for (var_idx, var_name) in variable_names.iter().enumerate() {
                if var_idx >= 128 {
                    break;
                }

                // Match literal presence (e.g. "v0", "v0'", "!v0")
                let neg_name1 = format!("{}'", var_name);
                let neg_name2 = format!("!{}", var_name);
                let neg_name3 = format!("~{}", var_name);

                if clean_term.contains(&neg_name1)
                    || clean_term.contains(&neg_name2)
                    || clean_term.contains(&neg_name3)
                {
                    required_mask |= 1u128 << var_idx;
                    // expected bit is 0
                } else if clean_term.contains(var_name) {
                    required_mask |= 1u128 << var_idx;
                    expected_bits |= 1u128 << var_idx;
                }
            }

            if required_mask != 0 {
                clauses.push(DynamicCompiledClause {
                    clause_id: format!("SATGUARDIAN-OPT-{:03}", idx + 1),
                    description: format!("Dynamically minimized invariant term: {}", clean_term),
                    required_mask,
                    expected_bits,
                    category: AttackCategory::Unknown,
                });
            }
        }

        clauses
    }
}
