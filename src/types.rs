use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Formal attack classification categories according to the Exactor Methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackCategory {
    Benign,
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    Ssrf,
    GraphqlAbuse,
    PrototypePollution,
    GrpcSmuggling,
    JwtTampering,
    CredentialStuffing,
    RateLimitDdos,
    CmsWordpressProbe,
    SensitiveExposureProbe,
    FrameworkExploitProbe,
    BusinessRuleViolation,
    Unknown,
}

impl AttackCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttackCategory::Benign => "benign",
            AttackCategory::SqlInjection => "sql_injection",
            AttackCategory::Xss => "xss",
            AttackCategory::CommandInjection => "command_injection",
            AttackCategory::PathTraversal => "path_traversal",
            AttackCategory::Ssrf => "ssrf",
            AttackCategory::GraphqlAbuse => "graphql_abuse",
            AttackCategory::PrototypePollution => "prototype_pollution",
            AttackCategory::GrpcSmuggling => "grpc_smuggling",
            AttackCategory::JwtTampering => "jwt_tampering",
            AttackCategory::CredentialStuffing => "credential_stuffing",
            AttackCategory::RateLimitDdos => "rate_limit_ddos",
            AttackCategory::CmsWordpressProbe => "cms_wordpress_probe",
            AttackCategory::SensitiveExposureProbe => "sensitive_exposure_probe",
            AttackCategory::FrameworkExploitProbe => "framework_exploit_probe",
            AttackCategory::BusinessRuleViolation => "business_rule_violation",
            AttackCategory::Unknown => "unknown",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            AttackCategory::Benign => "BENIGN TRAFFIC",
            AttackCategory::SqlInjection => "SQL INJECTION (SQLi)",
            AttackCategory::Xss => "CROSS-SITE SCRIPTING (XSS)",
            AttackCategory::CommandInjection => "COMMAND INJECTION / RCE",
            AttackCategory::PathTraversal => "PATH TRAVERSAL / LFI",
            AttackCategory::Ssrf => "SERVER-SIDE REQUEST FORGERY (SSRF)",
            AttackCategory::GraphqlAbuse => "GRAPHQL AST INJECTION / ABUSE",
            AttackCategory::PrototypePollution => "PROTOTYPE POLLUTION / JSON SMUGGLING",
            AttackCategory::GrpcSmuggling => "GRPC / PROTOBUF PROTOCOL ANOMALY",
            AttackCategory::JwtTampering => "JWT TAMPERING / ALGORITHM CONFUSION",
            AttackCategory::CredentialStuffing => "CREDENTIAL STUFFING / BRUTE FORCE",
            AttackCategory::RateLimitDdos => "LAYER-7 RATE LIMIT EXCEEDED / DDOS",
            AttackCategory::CmsWordpressProbe => "WORDPRESS RECONNAISSANCE / CMS PROBE",
            AttackCategory::SensitiveExposureProbe => "SENSITIVE FILE / BACKDOOR EXPOSURE PROBE",
            AttackCategory::FrameworkExploitProbe => "FRAMEWORK EXPLOIT PROBE (LOG4J/SPRING/LARAVEL)",
            AttackCategory::BusinessRuleViolation => "CUSTOMER BUSINESS POLICY VIOLATION",
            AttackCategory::Unknown => "UNKNOWN ANOMALY",
        }
    }
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// The deterministic perimeter defense action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackDecision {
    Allow,
    Block,
}

/// Evaluation execution tier within the neuro-symbolic WAF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionPath {
    FastPathLocal,
    HotCompiledDynamic,
    OracleEscalation,
}

/// Represents an incoming HTTP request inspected by the WAF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestPayload {
    pub id: String,
    pub method: String,
    pub path: String,
    pub query_string: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub client_ip: Option<String>,
}

impl HttpRequestPayload {
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            method: method.into(),
            path: path.into(),
            query_string: query.into(),
            headers: HashMap::new(),
            body: body.into(),
            client_ip: None,
        }
    }

    pub fn with_ip(
        method: impl Into<String>,
        path: impl Into<String>,
        query: impl Into<String>,
        body: impl Into<String>,
        client_ip: impl Into<String>,
    ) -> Self {
        let mut req = Self::new(method, path, query, body);
        req.client_ip = Some(client_ip.into());
        req
    }

    pub fn full_inspectable_string(&self) -> String {
        let mut parts = Vec::with_capacity(6);
        parts.push(self.path.clone());
        if !self.query_string.is_empty() {
            parts.push(self.query_string.clone());
        }
        if !self.body.is_empty() {
            parts.push(self.body.clone());
        }
        for (k, v) in &self.headers {
            let kl = k.to_ascii_lowercase();
            if kl == "user-agent"
                || kl == "cookie"
                || kl == "referer"
                || kl == "x-forwarded-for"
                || kl == "authorization"
                || kl == "host"
            {
                parts.push(format!("{}: {}", k, v));
            }
        }
        parts.join(" ")
    }
}

/// A formal domain in the AST invariant space (Certainty Island).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertaintyIsland {
    pub island_id: String,
    pub name: String,
    pub category: AttackCategory,
    pub description: String,
    pub formal_invariant: String,
    pub confidence: f64,
}

/// A formal invariant deduction rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeductionRule {
    pub rule_id: String,
    pub island_id: String,
    pub category: AttackCategory,
    pub name: String,
    pub description: String,
    pub invariant_formula: String,
    pub confidence: f64,
}

/// Mathematically verifiable causal proof chain explaining a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChain {
    pub request_id: String,
    pub is_violation: bool,
    pub category: AttackCategory,
    pub action: AttackDecision,
    pub execution_path: ExecutionPath,
    pub matched_rules: Vec<DeductionRule>,
    pub active_islands: Vec<String>,
    pub active_tokens: Vec<String>,
    pub deduction_steps: Vec<String>,
    pub formal_proof_latex: String,
    pub causal_proof: String,
    pub execution_time_us: f64,
}

/// Live telemetry & metrics summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafMetricsSnapshot {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub avg_latency_us: f64,
    pub p99_latency_us: f64,
    pub uptime_seconds: u64,
    pub active_rules_count: usize,
    pub hot_compiled_rules_count: usize,
    pub pending_anomalies: usize,
}
