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
    // Injection coverage islands (v2)
    "v40_nosql_operator",
    "v41_ssti_expression",
    "v42_crlf_header_injection",
    "v43_host_header_anomaly",
    "v44_malicious_upload",
    "v45_sqli_danger_func",
    "v46_xxe_entity",
    // Injection coverage islands (v3)
    "v47_sqli_subquery",
    "v48_sqli_case_having",
    "v49_cmd_ifs_binary",
    "v50_ssti_arith",
    "v51_ssti_embedded",
    "v52_ssrf_userinfo",
    "v53_ssrf_scheme_rel",
    "v54_ldap_injection",
    "v55_deserialization",
    "v56_host_absolute_uri",
    "v57_xpath_injection",
    "v58_graphql_abuse",
    "v59_method_override_abuse",
    // Protocol/semantic layer (v6)
    "v60_smuggling_desync",
    "v61_webdav_method",
    "v62_privileged_field",
    "v63_numeric_anomaly",
    "v64_nested_quantifier",
    "v65_csv_formula",
    "v66_log_forgery",
    "v67_cache_deception",
    "v68_ansi_escape",
    "v69_punycode_host",
    "v70_saml_protocol",
    "v71_oauth_redirect_abuse",
    "v72_xslt_stylesheet",
    "v73_xquery_expr",
    "v74_smtp_command",
    "v75_jsonrpc_exec",
    "v76_absolute_upload_path",
    "v77_soap_action_abuse",
    "v78_hidden_chars",
    "v79_keyword_smuggling",
    "v80_cache_poisoning_signal",
    "v81_oauth_flow_anomaly",
    "v82_mixed_script_evasion",
    "v83_param_path_traversal",
    "v84_cms_plugin_probe",
    "v85_cross_param_numeric",
    "v86_parameter_pollution",
    "v87_type_juggling",
    "v88_protocol_injection",
    "v89_connect_tunnel",
    "v90_webhook_ssrf",
    "v91_http2_pseudo_header",
    "v92_management_endpoint",
    "v93_open_redirect",
    "v94_content_type_confusion",
    "v95_integer_overflow",
    "v96_websocket_abuse",
    "v97_spring4shell",
    "v98_java_attack",
    "v99_sqli_extended",
    "v100_rce_extended",
    "v101_protocol_enforcement",
    "v102_php_injection",
    "v103_nodejs_injection",
    "v104_xss_extended",
    "v105_lfi_extended",
    "v106_rfi_scheme",
    "v107_session_token_url",
    // Java attack split (v108-v109)
    "v108_java_deserialization_gadget",
    "v109_java_runtime_sink",
    "v110_client_ip_spoof",
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

        if tokens.has_quote {
            fv.set(0);
        }
        if tokens.has_tautology {
            fv.set(1);
        }
        if tokens.has_union_select {
            fv.set(2);
        }
        if tokens.has_time_delay {
            fv.set(3);
        }
        if tokens.has_stacked_ddl {
            fv.set(4);
        }
        if tokens.has_script_tag {
            fv.set(5);
        }
        if tokens.has_event_handler {
            fv.set(6);
        }
        if tokens.has_js_scheme {
            fv.set(7);
        }
        if tokens.has_svg_onload {
            fv.set(8);
        }
        if tokens.has_shell_chain {
            fv.set(9);
        }
        if tokens.has_subshell {
            fv.set(10);
        }
        if tokens.has_dynamic_eval {
            fv.set(11);
        }
        if tokens.has_path_traversal {
            fv.set(12);
        }
        if tokens.has_sensitive_system_path {
            fv.set(13);
        }
        if tokens.has_ssrf_metadata {
            fv.set(14);
        }
        if tokens.has_high_entropy {
            fv.set(15);
        }
        if tokens.is_obfuscated {
            fv.set(16);
        }

        // Contextual features
        let ua = req
            .headers
            .get("user-agent")
            .map(|s| s.as_str())
            .unwrap_or("");
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
        if tokens.has_graphql_introspection {
            fv.set(24);
        }
        if tokens.has_graphql_deep_nesting {
            fv.set(25);
        }
        if tokens.has_graphql_batching {
            fv.set(26);
        }
        if tokens.has_proto_pollution {
            fv.set(27);
        }
        if tokens.has_json_deep_nesting {
            fv.set(28);
        }
        if tokens.has_grpc_smuggling {
            fv.set(29);
        }
        if tokens.has_grpc_status_injection {
            fv.set(30);
        }
        if tokens.has_jwt_alg_none {
            fv.set(31);
        }
        if tokens.has_jwt_missing_sig {
            fv.set(32);
        }
        if tokens.has_jwt_header_injection {
            fv.set(33);
        }

        // Stateful Behavioral
        if tokens.has_stateful_rate_limit {
            fv.set(34);
        }
        if tokens.has_stateful_credential_stuffing {
            fv.set(35);
        }

        // Modular Protection Islands
        if tokens.has_wordpress_probe {
            fv.set(36);
        }
        if tokens.has_sensitive_file_probe {
            fv.set(37);
        }
        if tokens.has_framework_exploit_probe {
            fv.set(38);
        }

        // Injection coverage islands (v2)
        if tokens.has_nosql_operator {
            fv.set(40);
        }
        if tokens.has_ssti_expression {
            fv.set(41);
        }
        if tokens.has_crlf_header_injection {
            fv.set(42);
        }
        if tokens.has_host_header_anomaly {
            fv.set(43);
        }
        if tokens.has_malicious_upload {
            fv.set(44);
        }
        if tokens.has_sqli_danger_func {
            fv.set(45);
        }
        if tokens.has_xxe_entity {
            fv.set(46);
        }

        // Injection coverage islands (v3)
        if tokens.has_sqli_subquery {
            fv.set(47);
        }
        if tokens.has_sqli_case_having {
            fv.set(48);
        }
        if tokens.has_cmd_ifs_binary {
            fv.set(49);
        }
        if tokens.has_ssti_arith {
            fv.set(50);
        }
        if tokens.has_ssti_embedded {
            fv.set(51);
        }
        if tokens.has_ssrf_userinfo {
            fv.set(52);
        }
        if tokens.has_ssrf_scheme_rel {
            fv.set(53);
        }
        if tokens.has_ldap_injection {
            fv.set(54);
        }
        if tokens.has_deserialization {
            fv.set(55);
        }
        if tokens.has_host_absolute_uri {
            fv.set(56);
        }
        if tokens.has_xpath_injection {
            fv.set(57);
        }
        if tokens.has_graphql_abuse {
            fv.set(58);
        }
        if tokens.has_method_override_abuse {
            fv.set(59);
        }

        // Protocol/semantic layer (v6)
        if tokens.has_smuggling_desync {
            fv.set(60);
        }
        if tokens.has_webdav_method {
            fv.set(61);
        }
        if tokens.has_privileged_field {
            fv.set(62);
        }
        if tokens.has_numeric_anomaly {
            fv.set(63);
        }
        if tokens.has_nested_quantifier {
            fv.set(64);
        }
        if tokens.has_csv_formula {
            fv.set(65);
        }
        if tokens.has_log_forgery {
            fv.set(66);
        }
        if tokens.has_cache_deception {
            fv.set(67);
        }
        if tokens.has_ansi_escape {
            fv.set(68);
        }
        if tokens.has_punycode_host {
            fv.set(69);
        }
        if tokens.has_saml_protocol {
            fv.set(70);
        }
        if tokens.has_oauth_redirect_abuse {
            fv.set(71);
        }
        if tokens.has_xslt_stylesheet {
            fv.set(72);
        }
        if tokens.has_xquery_expr {
            fv.set(73);
        }
        if tokens.has_smtp_command {
            fv.set(74);
        }
        if tokens.has_jsonrpc_exec {
            fv.set(75);
        }
        if tokens.has_absolute_upload_path {
            fv.set(76);
        }
        if tokens.has_soap_action_abuse {
            fv.set(77);
        }
        if tokens.has_hidden_chars {
            fv.set(78);
        }
        if tokens.has_keyword_smuggling {
            fv.set(79);
        }

        // Generalized lex proposals (v6.x pipeline output)
        if tokens.has_cache_poisoning_signal {
            fv.set(80);
        }
        if tokens.has_oauth_oidc_signal {
            fv.set(81);
        }
        if tokens.has_unicode_normalization_signal {
            fv.set(82);
        }
        if tokens.has_path_traversal_signal {
            fv.set(83);
        }
        if tokens.has_cms_wordpress_probe_signal {
            fv.set(84);
        }
        if tokens.has_business_logic_signal {
            fv.set(85);
        }

        // v7 lex proposals
        if tokens.has_parameter_pollution_signal {
            fv.set(86);
        }
        if tokens.has_type_juggling_signal {
            fv.set(87);
        }
        if tokens.has_protocol_injection_signal {
            fv.set(88);
        }
        if tokens.has_connect_tunnel_signal {
            fv.set(89);
        }
        if tokens.has_webhook_ssrf_signal {
            fv.set(90);
        }
        if tokens.has_http2_pseudo_header {
            fv.set(91);
        }
        if tokens.has_management_endpoint_signal {
            fv.set(92);
        }
        if tokens.has_open_redirect_signal {
            fv.set(93);
        }
        if tokens.has_content_type_confusion_signal {
            fv.set(94);
        }
        if tokens.has_integer_overflow_signal {
            fv.set(95);
        }
        if tokens.has_websocket_abuse_signal {
            fv.set(96);
        }
        if tokens.has_spring4shell_signal {
            fv.set(97);
        }
        if tokens.has_java_attack_signal {
            fv.set(98);
        }
        if tokens.has_sqli_extended_signal {
            fv.set(99);
        }
        if tokens.has_rce_extended_signal {
            fv.set(100);
        }
        if tokens.has_protocol_enforcement_signal {
            fv.set(101);
        }
        if tokens.has_php_injection_signal {
            fv.set(102);
        }
        if tokens.has_nodejs_injection_signal {
            fv.set(103);
        }
        if tokens.has_xss_extended_signal {
            fv.set(104);
        }
        if tokens.has_lfi_extended_signal {
            fv.set(105);
        }
        if tokens.has_rfi_scheme_signal {
            fv.set(106);
        }
        if tokens.has_session_token_url_signal {
            fv.set(107);
        }
        if tokens.has_java_deserialization_signal {
            fv.set(108);
        }
        if tokens.has_java_runtime_sink {
            fv.set(109);
        }
        if tokens.has_client_ip_spoof {
            fv.set(110);
        }

        fv
    }

    /// Returns standard variable list formatted for the SATGuardian Cloud Simplification API.
    pub fn get_variable_catalog(var_count: usize) -> Vec<String> {
        let count = var_count.min(FEATURE_NAMES.len());
        FEATURE_NAMES[..count]
            .iter()
            .map(|&s| s.to_string())
            .collect()
    }
}
