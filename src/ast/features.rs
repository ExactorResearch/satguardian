use crate::ast::lexer::LexicalTokens;
use crate::types::HttpRequestPayload;

/// Formal mapping of AST predicates to up to 128 boolean variables.
pub const FEATURE_NAMES: &[&str] = &[
    "v0_quote",
    "v1_tautology",
    "v2_union_select",
    "v3_time_delay",
    "v4_stacked_ddl",
    "v5_script_tag",
    "v6_event_handler",
    "v7_js_scheme",
    "v8_svg_onload",
    "v9_shell_chain",
    "v10_subshell",
    "v11_dynamic_eval",
    "v12_path_traversal",
    "v13_system_target",
    "v14_ssrf_metadata",
    "v15_high_entropy",
    "v16_obfuscated",
    "v17_empty_user_agent",
    "v18_post_method",
    "v19_admin_endpoint",
    "v20_large_body",
    "v21_null_byte",
    "v22_cmd_binaries",
    "v23_suspicious_header",
    // Enterprise & Banking Grammars
    "v24_graphql_introspection",
    "v25_graphql_deep_nesting",
    "v26_graphql_batching",
    "v27_proto_pollution",
    "v28_json_deep_nesting",
    "v29_grpc_smuggling",
    "v30_grpc_status_injection",
    "v31_jwt_alg_none",
    "v32_jwt_missing_sig",
    "v33_jwt_header_injection",
    // Stateful Behavioral
    "v34_stateful_rate_limit",
    "v35_stateful_credential_stuffing",
    // Modular Protection Islands
    "v36_wordpress_probe",
    "v37_sensitive_exposure",
    "v38_framework_exploit",
    "v39_business_violation",
];

/// Binarized request state representing a point on the Boolean Hypercube $\{0, 1\}^N$.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureVector {
    pub bits: u128,
}

impl FeatureVector {
    pub fn is_set(&self, index: usize) -> bool {
        if index >= 128 {
            return false;
        }
        (self.bits & (1u128 << index)) != 0
    }

    pub fn set(&mut self, index: usize) {
        if index < 128 {
            self.bits |= 1u128 << index;
        }
    }

    /// Returns the integer minterm representation for SATGuardian core minimization.
    pub fn as_minterm(&self) -> u128 {
        self.bits
    }

    /// Returns the list of active variable names for this vector.
    pub fn active_variable_names(&self) -> Vec<String> {
        let mut list = Vec::new();
        for (i, name) in FEATURE_NAMES.iter().enumerate() {
            if self.is_set(i) {
                list.push((*name).to_string());
            }
        }
        list
    }
}

/// Feature Binarizer: converts an incoming request and its AST tokens into a FeatureVector.
pub struct FeatureBinarizer;

impl FeatureBinarizer {
    pub fn binarize(req: &HttpRequestPayload, tokens: &LexicalTokens) -> FeatureVector {
        let mut fv = FeatureVector::default();

        if tokens.has_quote { fv.set(0); }
        if tokens.has_tautology { fv.set(1); }
        if tokens.has_union_select { fv.set(2); }
        if tokens.has_time_delay { fv.set(3); }
        if tokens.has_stacked_ddl { fv.set(4); }
        if tokens.has_script_tag { fv.set(5); }
        if tokens.has_event_handler { fv.set(6); }
        if tokens.has_js_scheme { fv.set(7); }
        if tokens.has_svg_onload { fv.set(8); }
        if tokens.has_shell_chain { fv.set(9); }
        if tokens.has_subshell { fv.set(10); }
        if tokens.has_dynamic_eval { fv.set(11); }
        if tokens.has_path_traversal { fv.set(12); }
        if tokens.has_sensitive_system_path { fv.set(13); }
        if tokens.has_ssrf_metadata { fv.set(14); }
        if tokens.has_high_entropy { fv.set(15); }
        if tokens.is_obfuscated { fv.set(16); }

        // Contextual features
        let ua = req.headers.get("user-agent").map(|s| s.as_str()).unwrap_or("");
        if ua.trim().is_empty() {
            fv.set(17);
        }

        if req.method.eq_ignore_ascii_case("POST") || req.method.eq_ignore_ascii_case("PUT") {
            fv.set(18);
        }

        let p_lower = req.path.to_ascii_lowercase();
        if p_lower.contains("admin") || p_lower.contains("login") || p_lower.contains("auth") {
            fv.set(19);
        }

        if req.body.len() > 4096 {
            fv.set(20);
        }

        let inspectable = req.full_inspectable_string();
        if inspectable.contains('\0') || inspectable.contains("%00") {
            fv.set(21);
        }

        // Enterprise & Banking Grammars
        if tokens.has_graphql_introspection { fv.set(24); }
        if tokens.has_graphql_deep_nesting { fv.set(25); }
        if tokens.has_graphql_batching { fv.set(26); }
        if tokens.has_proto_pollution { fv.set(27); }
        if tokens.has_json_deep_nesting { fv.set(28); }
        if tokens.has_grpc_smuggling { fv.set(29); }
        if tokens.has_grpc_status_injection { fv.set(30); }
        if tokens.has_jwt_alg_none { fv.set(31); }
        if tokens.has_jwt_missing_sig { fv.set(32); }
        if tokens.has_jwt_header_injection { fv.set(33); }

        // Stateful Behavioral
        if tokens.has_stateful_rate_limit { fv.set(34); }
        if tokens.has_stateful_credential_stuffing { fv.set(35); }

        // Modular Protection Islands
        if tokens.has_wordpress_probe { fv.set(36); }
        if tokens.has_sensitive_file_probe { fv.set(37); }
        if tokens.has_framework_exploit_probe { fv.set(38); }

        fv
    }

    /// Returns standard variable list formatted for the SATGuardian Cloud Simplification API.
    pub fn get_variable_catalog(var_count: usize) -> Vec<String> {
        let count = var_count.min(FEATURE_NAMES.len());
        FEATURE_NAMES[..count].iter().map(|&s| s.to_string()).collect()
    }
}
