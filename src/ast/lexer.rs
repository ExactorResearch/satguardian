use crate::ast::graphql::GraphqlAstAnalyzer;
use crate::ast::grpc::GrpcProtobufAnalyzer;
use crate::ast::json_rules::JsonStrictAnalyzer;
use crate::ast::jwt::JwtTamperingAnalyzer;
use crate::types::HttpRequestPayload;
use percent_encoding::percent_decode_str;
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Multi-pass recursive normalization and AST token extraction.
pub struct AstLexer;

/// Extracted AST lexical tokens found within an HTTP request.
#[derive(Debug, Clone, Default)]
pub struct LexicalTokens {
    pub normalized_text: String,
    pub has_quote: bool,
    pub has_tautology: bool,
    pub has_union_select: bool,
    pub has_time_delay: bool,
    pub has_stacked_ddl: bool,
    pub has_script_tag: bool,
    pub has_event_handler: bool,
    pub has_js_scheme: bool,
    pub has_svg_onload: bool,
    pub has_shell_chain: bool,
    pub has_subshell: bool,
    pub has_dynamic_eval: bool,
    pub has_path_traversal: bool,
    pub has_sensitive_system_path: bool,
    pub has_ssrf_metadata: bool,
    pub has_ssrf_private_ip: bool,
    pub has_high_entropy: bool,
    pub is_obfuscated: bool,
    // Banking & Enterprise Grammar tokens
    pub has_graphql_introspection: bool,
    pub has_graphql_deep_nesting: bool,
    pub has_graphql_batching: bool,
    pub has_proto_pollution: bool,
    pub has_json_deep_nesting: bool,
    pub has_grpc_smuggling: bool,
    pub has_grpc_status_injection: bool,
    pub has_jwt_alg_none: bool,
    pub has_jwt_missing_sig: bool,
    pub has_jwt_header_injection: bool,
    // Stateful Behavioral tokens
    pub has_stateful_rate_limit: bool,
    pub has_stateful_credential_stuffing: bool,
    // Modular Protection Islands tokens
    pub has_wordpress_probe: bool,
    pub has_sensitive_file_probe: bool,
    pub has_framework_exploit_probe: bool,
    pub active_token_names: Vec<String>,
}

// Pre-compiled regex singletons for ultra-low latency (< 10 microseconds)
static RE_TAUT_PAIR: OnceLock<Regex> = OnceLock::new();
static RE_TAUT_STATIC: OnceLock<Vec<Regex>> = OnceLock::new();
static RE_UNION_SELECT: OnceLock<Regex> = OnceLock::new();
static RE_SQL_SLEEP: OnceLock<Regex> = OnceLock::new();
static RE_STACKED_DDL: OnceLock<Regex> = OnceLock::new();
static RE_XSS_SCRIPT: OnceLock<Regex> = OnceLock::new();
static RE_XSS_EVENT: OnceLock<Regex> = OnceLock::new();
static RE_XSS_JS_URI: OnceLock<Regex> = OnceLock::new();
static RE_XSS_SVG: OnceLock<Regex> = OnceLock::new();
static RE_SHELL_CHAIN: OnceLock<Regex> = OnceLock::new();
static RE_SUBSHELL: OnceLock<Regex> = OnceLock::new();
static RE_DYNAMIC_EVAL: OnceLock<Regex> = OnceLock::new();
static RE_PATH_TRAVERSAL: OnceLock<Regex> = OnceLock::new();
static RE_PATH_DIRECT_SYSTEM: OnceLock<Regex> = OnceLock::new();
static RE_PATH_DOTS_ONLY: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_METADATA: OnceLock<Regex> = OnceLock::new();
static RE_COMMENT_STRIP: OnceLock<Regex> = OnceLock::new();
static RE_WORDPRESS_PROBE: OnceLock<Regex> = OnceLock::new();
static RE_SENSITIVE_EXPOSURE: OnceLock<Regex> = OnceLock::new();
static RE_FRAMEWORK_EXPLOIT: OnceLock<Regex> = OnceLock::new();

fn init_regexes() {
    let _ = RE_TAUT_PAIR.get_or_init(|| {
        Regex::new(r#"(?i)(?:or|and)\s+['"]?([a-zA-Z0-9_-]+)['"]?\s*=\s*['"]?([a-zA-Z0-9_-]+)['"]?"#).unwrap()
    });
    let _ = RE_TAUT_STATIC.get_or_init(|| {
        vec![
            Regex::new(r#"(?i)(?:or|and)\s+1\s*=\s*1"#).unwrap(),
            Regex::new(r#"(?i)(?:or|and)\s+true\b"#).unwrap(),
            Regex::new(r#"(?i)admin'--"#).unwrap(),
            Regex::new(r#"(?i)['"]\s*or\s*['"]"#).unwrap(),
        ]
    });
    let _ = RE_UNION_SELECT.get_or_init(|| {
        Regex::new(r#"(?i)\bunion\s+(?:all\s+)?select\b"#).unwrap()
    });
    let _ = RE_SQL_SLEEP.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\("#).unwrap()
    });
    let _ = RE_STACKED_DDL.get_or_init(|| {
        Regex::new(r#"(?i)(?:;|\bunion\b).*?\b(?:drop\s+table|truncate\s+table|alter\s+table|insert\s+into|delete\s+from)\b"#).unwrap()
    });
    let _ = RE_XSS_SCRIPT.get_or_init(|| {
        Regex::new(r#"(?is)<\s*script[^>]*>.*?(?:alert|eval|document|window|fetch|prompt|<|location)"#).unwrap()
    });
    let _ = RE_XSS_EVENT.get_or_init(|| {
        Regex::new(r#"(?i)<\s*[a-z0-9_-]+[^>]*[\s/]on[a-z]+\s*=\s*['"]?[^'">]+"#).unwrap()
    });
    let _ = RE_XSS_JS_URI.get_or_init(|| {
        Regex::new(r#"(?i)(?:javascript|vbscript|data):[^\s'"]+"#).unwrap()
    });
    let _ = RE_XSS_SVG.get_or_init(|| {
        Regex::new(r#"(?i)<\s*svg[\s/]+onload\s*="#).unwrap()
    });
    let _ = RE_SHELL_CHAIN.get_or_init(|| {
        Regex::new(r#"(?i)(?:;|\|\||\||&&|`|\$\([^)]+\))\s*(?:cat|bash|curl|wget|nc|whoami|id|sh|powershell|cmd\.exe|type|ls|netstat|uname)\b"#).unwrap()
    });
    let _ = RE_SUBSHELL.get_or_init(|| {
        Regex::new(r#"(?i)(?:`[^`]+`|\$\([^)]+\))"#).unwrap()
    });
    let _ = RE_DYNAMIC_EVAL.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:os\.system|subprocess\.|eval\(|exec\(|runtime\.getruntime\(\)\.exec|passthru\(|shell_exec\()\b"#).unwrap()
    });
    let _ = RE_PATH_TRAVERSAL.get_or_init(|| {
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|%252e%252e%252f)(?:.*?(?:etc/passwd|etc/shadow|boot\.ini|windows/win\.ini|proc/self))"#).unwrap()
    });
    let _ = RE_PATH_DIRECT_SYSTEM.get_or_init(|| {
        Regex::new(r#"(?i)(?:/proc/self/(?:environ|cmdline|maps)|/etc/passwd|/etc/shadow|/windows/win\.ini|c:[/\\]boot\.ini)"#).unwrap()
    });
    let _ = RE_PATH_DOTS_ONLY.get_or_init(|| {
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f){2,}"#).unwrap()
    });
    let _ = RE_SSRF_METADATA.get_or_init(|| {
        Regex::new(r#"(?i)(?:https?|gopher|dict|file)://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|instance-data|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})"#).unwrap()
    });
    let _ = RE_COMMENT_STRIP.get_or_init(|| {
        Regex::new(r#"/\*.*?\*/"#).unwrap()
    });
    let _ = RE_WORDPRESS_PROBE.get_or_init(|| {
        Regex::new(r#"(?i)(?:/wp-(?:admin|login\.php|includes|content|cron\.php|config\.php|json/wp/)|xmlrpc\.php|\?author=\d+|wlwmanifest\.xml|^/?(?:index|wp)\.php(?:$|\?))"#).unwrap()
    });
    let _ = RE_SENSITIVE_EXPOSURE.get_or_init(|| {
        Regex::new(r#"(?i)(?:/\.env(?:\.[a-z0-9_-]+)?|/\.git(?:/|$|\?)|/\.aws/credentials|/(?:phpmyadmin|pma|adminer\.php|actuator(?:/[a-z]+)?|swagger-ui|\.svn|docker-compose\.ya?ml|Dockerfile|dump\.sql|backup\.sql|web\.config))"#).unwrap()
    });
    let _ = RE_FRAMEWORK_EXPLOIT.get_or_init(|| {
        Regex::new(r#"(?i)(?:\$\{jndi:(?:ldap|rmi|dns|corba|iiop)|#\{T\([a-z0-9_.]+\)|\$\{T\([a-z0-9_.]+\)|_ignition/execute-solution|invokefunction&function=call_user_func)"#).unwrap()
    });
}

impl AstLexer {
    /// Multi-pass recursive URL decode and comment stripper.
    pub fn normalize_string(raw: &str) -> (String, bool) {
        init_regexes();
        let mut is_obfuscated = false;
        if raw.contains('%') || raw.contains("/**/") {
            is_obfuscated = true;
        }

        // Pass 1: Decode
        let d1 = percent_decode_str(raw).decode_utf8_lossy().to_string();
        // Pass 2: Nested decode
        let d2 = percent_decode_str(&d1).decode_utf8_lossy().to_string();
        // Pass 3: Strip SQL comments (/**/)
        let re_comment = RE_COMMENT_STRIP.get().unwrap();
        let d3 = re_comment.replace_all(&d2, " ").to_string();

        let combined = format!("{} {} {} {}", raw, d1, d2, d3);
        (combined, is_obfuscated)
    }

    /// Computes Shannon entropy of payload to detect encrypted or obfuscated binary shells.
    pub fn calculate_entropy(data: &str) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut frequencies = [0usize; 256];
        for b in data.bytes() {
            frequencies[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &frequencies {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Performs lexical AST token extraction on target raw input.
    pub fn tokenize(raw_text: &str) -> LexicalTokens {
        init_regexes();
        let (normalized, is_obfuscated) = Self::normalize_string(raw_text);
        let entropy = Self::calculate_entropy(raw_text);
        let has_high_entropy = entropy > 4.8 && raw_text.len() > 32;

        let mut tokens = LexicalTokens {
            normalized_text: normalized.clone(),
            has_high_entropy,
            is_obfuscated,
            ..Default::default()
        };

        let norm_lower = normalized.to_ascii_lowercase();

        // 1. SQL Injection Tokens
        tokens.has_quote = normalized.contains('\'') || normalized.contains('"');
        if let Some(re_pair) = RE_TAUT_PAIR.get() {
            for cap in re_pair.captures_iter(&normalized) {
                if let (Some(left), Some(right)) = (cap.get(1), cap.get(2)) {
                    if left.as_str().eq_ignore_ascii_case(right.as_str()) {
                        tokens.has_tautology = true;
                        tokens.active_token_names.push("TAUTOLOGY_EQUALS".to_string());
                        break;
                    }
                }
            }
        }
        if !tokens.has_tautology {
            if let Some(statics) = RE_TAUT_STATIC.get() {
                for taut in statics {
                    if taut.is_match(&normalized) {
                        tokens.has_tautology = true;
                        tokens.active_token_names.push("TAUTOLOGY_EQUALS".to_string());
                        break;
                    }
                }
            }
        }
        if RE_UNION_SELECT.get().unwrap().is_match(&normalized) {
            tokens.has_union_select = true;
            tokens.active_token_names.push("UNION_CLAUSE".to_string());
            tokens.active_token_names.push("SELECT_PROJECTION".to_string());
        }
        if RE_SQL_SLEEP.get().unwrap().is_match(&normalized) {
            tokens.has_time_delay = true;
            tokens.active_token_names.push("TIME_DELAY_FUNCTION".to_string());
        }
        if RE_STACKED_DDL.get().unwrap().is_match(&normalized) {
            tokens.has_stacked_ddl = true;
            tokens.active_token_names.push("STACKED_DDL".to_string());
        }

        // 2. XSS Tokens
        if RE_XSS_SCRIPT.get().unwrap().is_match(&normalized)
            || (norm_lower.contains("<script") && norm_lower.contains("</script"))
        {
            tokens.has_script_tag = true;
            tokens.active_token_names.push("SCRIPT_ELEMENT".to_string());
        }
        if RE_XSS_EVENT.get().unwrap().is_match(&normalized) {
            tokens.has_event_handler = true;
            tokens.active_token_names.push("INLINE_EVENT_HANDLER".to_string());
        }
        if RE_XSS_SVG.get().unwrap().is_match(&normalized) {
            tokens.has_svg_onload = true;
            tokens.active_token_names.push("SVG_ONLOAD".to_string());
        }
        if RE_XSS_JS_URI.get().unwrap().is_match(&normalized) {
            tokens.has_js_scheme = true;
            tokens.active_token_names.push("JS_URI_SCHEME".to_string());
        }

        // 3. Command Injection / RCE Tokens
        if RE_SHELL_CHAIN.get().unwrap().is_match(&normalized) {
            tokens.has_shell_chain = true;
            tokens.active_token_names.push("SHELL_METACHAR".to_string());
            tokens.active_token_names.push("SYSTEM_BINARY_INVOCATION".to_string());
        }
        if RE_SUBSHELL.get().unwrap().is_match(&normalized) {
            let has_bin = ["cat", "curl", "wget", "id", "whoami", "uname", "ls", "bash", "sh"]
                .iter()
                .any(|&bin| norm_lower.contains(bin));
            if has_bin {
                tokens.has_subshell = true;
                tokens.active_token_names.push("SUBSHELL_EXPANSION".to_string());
            }
        }
        if RE_DYNAMIC_EVAL.get().unwrap().is_match(&normalized) {
            tokens.has_dynamic_eval = true;
            tokens.active_token_names.push("DYNAMIC_CODE_RUNTIME".to_string());
        }

        // 4. Path Traversal Tokens
        if RE_PATH_TRAVERSAL.get().unwrap().is_match(&normalized)
            || (RE_PATH_DOTS_ONLY.get().unwrap().is_match(&normalized)
                && (raw_text.contains('/') || raw_text.contains('\\') || raw_text.contains('%')))
        {
            tokens.has_path_traversal = true;
            tokens.active_token_names.push("DIR_TRAVERSAL_DOT_DOT".to_string());
        }
        if RE_PATH_DIRECT_SYSTEM.get().unwrap().is_match(&normalized) {
            tokens.has_sensitive_system_path = true;
            tokens.active_token_names.push("DIRECT_SYSTEM_FILE_TARGET".to_string());
        }

        // 5. SSRF Tokens (requires URL scheme directly targeting loopback, RFC1918, or cloud metadata)
        if RE_SSRF_METADATA.get().unwrap().is_match(&normalized) {
            tokens.has_ssrf_metadata = true;
            tokens.active_token_names.push("CLOUD_METADATA_ENDPOINT".to_string());
        }

        // 6. GraphQL Tokens (raw text / fallback inspection)
        let gql = GraphqlAstAnalyzer::analyze("", raw_text, "");
        if gql.has_introspection {
            tokens.has_graphql_introspection = true;
            tokens.active_token_names.extend(gql.active_tokens.clone());
        }
        if gql.has_deep_nesting {
            tokens.has_graphql_deep_nesting = true;
            tokens.active_token_names.extend(gql.active_tokens.clone());
        }
        if gql.has_batching {
            tokens.has_graphql_batching = true;
            tokens.active_token_names.extend(gql.active_tokens.clone());
        }

        // 7. JSON Strict & Prototype Pollution
        let js = JsonStrictAnalyzer::analyze(raw_text);
        if js.has_proto_pollution {
            tokens.has_proto_pollution = true;
            tokens.active_token_names.extend(js.active_tokens.clone());
        }
        if js.has_deep_nesting {
            tokens.has_json_deep_nesting = true;
            tokens.active_token_names.extend(js.active_tokens.clone());
        }

        // 8. JWT Tampering & Algorithm Confusion
        let empty_headers = HashMap::new();
        let jwt = JwtTamperingAnalyzer::analyze(&empty_headers, raw_text);
        if jwt.has_alg_none {
            tokens.has_jwt_alg_none = true;
            tokens.active_token_names.extend(jwt.active_tokens.clone());
        }
        if jwt.has_missing_signature {
            tokens.has_jwt_missing_sig = true;
            tokens.active_token_names.extend(jwt.active_tokens.clone());
        }
        if jwt.has_header_injection {
            tokens.has_jwt_header_injection = true;
            tokens.active_token_names.extend(jwt.active_tokens.clone());
        }

        // 9. Modular Protection Island Tokens
        if RE_WORDPRESS_PROBE.get().unwrap().is_match(&normalized) {
            tokens.has_wordpress_probe = true;
            tokens.active_token_names.push("WORDPRESS_RECON_PROBE".to_string());
        }
        if RE_SENSITIVE_EXPOSURE.get().unwrap().is_match(&normalized) {
            tokens.has_sensitive_file_probe = true;
            tokens.active_token_names.push("SENSITIVE_FILE_EXPOSURE_PROBE".to_string());
        }
        if RE_FRAMEWORK_EXPLOIT.get().unwrap().is_match(&normalized) {
            tokens.has_framework_exploit_probe = true;
            tokens.active_token_names.push("FRAMEWORK_EXPLOIT_PAYLOAD".to_string());
        }

        tokens.active_token_names.sort();
        tokens.active_token_names.dedup();
        tokens
    }

    /// Full-fidelity HTTP request tokenizer combining headers, body, framing, and AST grammars.
    pub fn tokenize_request(req: &HttpRequestPayload) -> LexicalTokens {
        let inspectable = req.full_inspectable_string();
        let mut tokens = Self::tokenize(&inspectable);

        // A. GraphQL AST Grammar Analyzer
        let gql = GraphqlAstAnalyzer::analyze(&req.path, &req.body, &req.query_string);
        if gql.has_introspection {
            tokens.has_graphql_introspection = true;
        }
        if gql.has_deep_nesting {
            tokens.has_graphql_deep_nesting = true;
        }
        if gql.has_batching {
            tokens.has_graphql_batching = true;
        }
        tokens.active_token_names.extend(gql.active_tokens);

        // B. Strict JSON Schema & Prototype Pollution
        let js = JsonStrictAnalyzer::analyze(&req.body);
        if js.has_proto_pollution {
            tokens.has_proto_pollution = true;
        }
        if js.has_deep_nesting {
            tokens.has_json_deep_nesting = true;
        }
        tokens.active_token_names.extend(js.active_tokens);

        // C. gRPC / Protobuf Smuggling & Trailer Injection
        let grpc = GrpcProtobufAnalyzer::analyze(&req.headers, req.body.as_bytes());
        if grpc.has_grpc_smuggling {
            tokens.has_grpc_smuggling = true;
        }
        if grpc.has_grpc_status_injection {
            tokens.has_grpc_status_injection = true;
        }
        tokens.active_token_names.extend(grpc.active_tokens);

        // D. JWT Tampering & Algorithm Confusion
        let jwt = JwtTamperingAnalyzer::analyze(&req.headers, &inspectable);
        if jwt.has_alg_none {
            tokens.has_jwt_alg_none = true;
        }
        if jwt.has_missing_signature {
            tokens.has_jwt_missing_sig = true;
        }
        if jwt.has_header_injection {
            tokens.has_jwt_header_injection = true;
        }
        tokens.active_token_names.extend(jwt.active_tokens);

        // E. Direct Target & Path Specific Island Checks (ensures exact URI match)
        let path_and_query = format!("{}?{}", req.path, req.query_string);
        if RE_WORDPRESS_PROBE.get().unwrap().is_match(&path_and_query) {
            tokens.has_wordpress_probe = true;
            tokens.active_token_names.push("WORDPRESS_RECON_PROBE".to_string());
        }
        if RE_SENSITIVE_EXPOSURE.get().unwrap().is_match(&path_and_query) {
            tokens.has_sensitive_file_probe = true;
            tokens.active_token_names.push("SENSITIVE_FILE_EXPOSURE_PROBE".to_string());
        }
        let re_framework = RE_FRAMEWORK_EXPLOIT.get().unwrap();
        if re_framework.is_match(&path_and_query) || (!req.body.is_empty() && re_framework.is_match(&req.body)) {
            tokens.has_framework_exploit_probe = true;
            tokens.active_token_names.push("FRAMEWORK_EXPLOIT_PAYLOAD".to_string());
        }

        tokens.active_token_names.sort();
        tokens.active_token_names.dedup();
        tokens
    }
}
