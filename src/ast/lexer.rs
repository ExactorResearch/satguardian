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
    // Injection coverage islands (v2)
    pub has_nosql_operator: bool,
    pub has_ssti_expression: bool,
    pub has_crlf_header_injection: bool,
    pub has_host_header_anomaly: bool,
    pub has_malicious_upload: bool,
    pub has_sqli_danger_func: bool,
    pub has_xxe_entity: bool,
    // Injection coverage islands (v3)
    pub has_sqli_subquery: bool,
    pub has_sqli_case_having: bool,
    pub has_cmd_ifs_binary: bool,
    pub has_ssti_arith: bool,
    pub has_ssti_embedded: bool,
    pub has_ssrf_userinfo: bool,
    pub has_ssrf_scheme_rel: bool,
    pub has_ldap_injection: bool,
    pub has_deserialization: bool,
    pub has_xpath_injection: bool,
    pub has_host_absolute_uri: bool,
    pub has_method_override_abuse: bool,
    pub has_graphql_abuse: bool,
    // v6 protocol/semantic layer
    pub has_smuggling_desync: bool,
    pub has_webdav_method: bool,
    pub has_privileged_field: bool,
    pub has_numeric_anomaly: bool,
    pub has_nested_quantifier: bool,
    pub has_csv_formula: bool,
    pub has_log_forgery: bool,
    pub has_cache_deception: bool,
    pub has_ansi_escape: bool,
    pub has_punycode_host: bool,
    pub has_saml_protocol: bool,
    pub has_oauth_redirect_abuse: bool,
    pub has_xslt_stylesheet: bool,
    pub has_xquery_expr: bool,
    pub has_smtp_command: bool,
    pub has_jsonrpc_exec: bool,
    pub has_absolute_upload_path: bool,
    pub has_soap_action_abuse: bool,
    pub has_hidden_chars: bool,
    pub has_keyword_smuggling: bool,
    // v6.x lex proposals (generalized detectors, bits v80-v85)
    pub has_cache_poisoning_signal: bool,
    pub has_oauth_oidc_signal: bool,
    pub has_unicode_normalization_signal: bool,
    pub has_path_traversal_signal: bool,
    pub has_cms_wordpress_probe_signal: bool,
    pub has_business_logic_signal: bool,
    // v7 lex proposals (bits v86-v97)
    pub has_parameter_pollution_signal: bool,
    pub has_type_juggling_signal: bool,
    pub has_protocol_injection_signal: bool,
    pub has_connect_tunnel_signal: bool,
    pub has_webhook_ssrf_signal: bool,
    pub has_http2_pseudo_header: bool,
    pub has_management_endpoint_signal: bool,
    pub has_open_redirect_signal: bool,
    pub has_content_type_confusion_signal: bool,
    pub has_integer_overflow_signal: bool,
    pub has_websocket_abuse_signal: bool,
    pub has_spring4shell_signal: bool,
    // CRS rule-group coverage (v98-v107): language-runtime abuse classes.
    pub has_java_attack_signal: bool,
    pub has_sqli_extended_signal: bool,
    pub has_rce_extended_signal: bool,
    pub has_protocol_enforcement_signal: bool,
    pub has_php_injection_signal: bool,
    pub has_nodejs_injection_signal: bool,
    pub has_xss_extended_signal: bool,
    pub has_lfi_extended_signal: bool,
    pub has_rfi_scheme_signal: bool,
    pub has_session_token_url_signal: bool,
    // Java attack split: gadget-class names are deserialization evidence;
    // runtime exec sinks (Runtime.exec, ProcessBuilder, Class.forName) are
    // command-injection evidence, not serialization markers.
    pub has_java_deserialization_signal: bool,
    pub has_java_runtime_sink: bool,
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
static RE_COMMENT_STRIP: OnceLock<Regex> = OnceLock::new();
static RE_WORDPRESS_PROBE: OnceLock<Regex> = OnceLock::new();
static RE_SENSITIVE_EXPOSURE: OnceLock<Regex> = OnceLock::new();
static RE_FRAMEWORK_EXPLOIT: OnceLock<Regex> = OnceLock::new();
static RE_MYSQL_EXEC_COMMENT: OnceLock<Regex> = OnceLock::new();
static RE_JNDI_OBFUSCATION: OnceLock<Regex> = OnceLock::new();
static RE_JNDI_ENV_LOOKUP: OnceLock<Regex> = OnceLock::new();
static RE_TAUT_NUMERIC: OnceLock<Regex> = OnceLock::new();
static RE_OR_NUMERIC_COMMENT: OnceLock<Regex> = OnceLock::new();
static RE_OVERLONG_DOT: OnceLock<Regex> = OnceLock::new();
static RE_OVERLONG_SLASH: OnceLock<Regex> = OnceLock::new();
static RE_OVERLONG_BACKSLASH: OnceLock<Regex> = OnceLock::new();
static RE_IIS_DOT: OnceLock<Regex> = OnceLock::new();
static RE_IIS_SLASH: OnceLock<Regex> = OnceLock::new();
static RE_IIS_BACKSLASH: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_CLOUD: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_PRIVATE: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_PARAM_CONTEXT: OnceLock<Regex> = OnceLock::new();
static RE_XSS_REMOTE_SCRIPT: OnceLock<Regex> = OnceLock::new();
static RE_POWERSHELL_EXEC: OnceLock<Regex> = OnceLock::new();
static RE_BASE64_DECODE: OnceLock<Regex> = OnceLock::new();
static RE_NOSQL_JSON_OP: OnceLock<Regex> = OnceLock::new();
static RE_NOSQL_BRACKET_OP: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_JINJA: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_FREEMARKER: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_VELOCITY: OnceLock<Regex> = OnceLock::new();
static RE_CRLF_RESPONSE_HDR: OnceLock<Regex> = OnceLock::new();
static RE_UPLOAD_FILENAME: OnceLock<Regex> = OnceLock::new();
static RE_UPLOAD_CTX: OnceLock<Regex> = OnceLock::new();
static RE_SERVER_SIDE_TAG: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_ALT_TARGET: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_INTERNAL_TLD: OnceLock<Regex> = OnceLock::new();
static RE_WIN_SHELL_BINARY: OnceLock<Regex> = OnceLock::new();
static RE_SHELL_METACHAR_GATE: OnceLock<Regex> = OnceLock::new();
static RE_SQL_ERROR_FUNC: OnceLock<Regex> = OnceLock::new();
static RE_PHP_WRAPPER: OnceLock<Regex> = OnceLock::new();
static RE_SHELLSHOCK: OnceLock<Regex> = OnceLock::new();
static RE_PATH_BINARY: OnceLock<Regex> = OnceLock::new();
static RE_XXE_ENTITY: OnceLock<Regex> = OnceLock::new();
static RE_HEX_BLOB: OnceLock<Regex> = OnceLock::new();
static RE_JNDI_CHAR_EXTRACT: OnceLock<Regex> = OnceLock::new();
static RE_JNDI_DATE_LOOKUP: OnceLock<Regex> = OnceLock::new();
// Injection coverage islands (v3)
static RE_SQL_SUBQUERY: OnceLock<Regex> = OnceLock::new();
static RE_SQL_CASE_HAVING: OnceLock<Regex> = OnceLock::new();
static RE_UNION_SELECT_OBF: OnceLock<Regex> = OnceLock::new();
static RE_CMD_IFS_BINARY: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_ARITH: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_EMBEDDED: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_EXPR_PARAM: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_USERINFO: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_SCHEME_REL: OnceLock<Regex> = OnceLock::new();
static RE_LDAP_META: OnceLock<Regex> = OnceLock::new();
static RE_DESERIALIZATION: OnceLock<Regex> = OnceLock::new();
static RE_PHP_FUNC_CALLBACK: OnceLock<Regex> = OnceLock::new();
static RE_PHP_VAR_CALL: OnceLock<Regex> = OnceLock::new();
static RE_PHP_CONCAT_ASSIGN: OnceLock<Regex> = OnceLock::new();
static RE_WIN_LOLBIN: OnceLock<Regex> = OnceLock::new();
static RE_XPATH_EXPR: OnceLock<Regex> = OnceLock::new();
static RE_XPATH_FUNC: OnceLock<Regex> = OnceLock::new();
static RE_XPATH_AXIS: OnceLock<Regex> = OnceLock::new();
static RE_UNC_PATH: OnceLock<Regex> = OnceLock::new();
static RE_UNC_BENIGN_EXT: OnceLock<Regex> = OnceLock::new();
static RE_ADS_PATH: OnceLock<Regex> = OnceLock::new();
static RE_CMD_EXEC_TRICK: OnceLock<Regex> = OnceLock::new();
static RE_NOSQL_ADMIN_CMD: OnceLock<Regex> = OnceLock::new();
static RE_SQL_JSON_FIELD: OnceLock<Regex> = OnceLock::new();
static RE_CRLF_ANY_HDR: OnceLock<Regex> = OnceLock::new();
static RE_CRLF_CONTENT_HDR: OnceLock<Regex> = OnceLock::new();
static RE_EMAIL_ENCODED_WORD: OnceLock<Regex> = OnceLock::new();
static RE_SSTI_SMARTY: OnceLock<Regex> = OnceLock::new();
static RE_SSRF_CLOUD_SCHEME: OnceLock<Regex> = OnceLock::new();
static RE_XXE_REF: OnceLock<Regex> = OnceLock::new();
static RE_PHP_DOLLAR_BRACE_CALL: OnceLock<Regex> = OnceLock::new();
static RE_PHP_EVAL_MODIFIER: OnceLock<Regex> = OnceLock::new();
static RE_PHP_GADGET_CLASS: OnceLock<Regex> = OnceLock::new();
static RE_NOSQL_DB_PATH: OnceLock<Regex> = OnceLock::new();
static RE_NESTED_QUANT: OnceLock<Regex> = OnceLock::new();
static RE_CSV_FORMULA: OnceLock<Regex> = OnceLock::new();
static RE_LOG_LINE: OnceLock<Regex> = OnceLock::new();
static RE_SAML_PROTO: OnceLock<Regex> = OnceLock::new();
static RE_XSLT: OnceLock<Regex> = OnceLock::new();
static RE_XQUERY: OnceLock<Regex> = OnceLock::new();
static RE_SMTP_CMD: OnceLock<Regex> = OnceLock::new();
static RE_JSONRPC_EXEC: OnceLock<Regex> = OnceLock::new();
static RE_ABS_UPLOAD_PATH: OnceLock<Regex> = OnceLock::new();
static RE_NUMERIC_ANOMALY: OnceLock<Regex> = OnceLock::new();
static RE_PRIVILEGED_KEY: OnceLock<Regex> = OnceLock::new();
static RE_WEBASSET_EXT: OnceLock<Regex> = OnceLock::new();
static RE_ACCT_PATH: OnceLock<Regex> = OnceLock::new();
static RE_REDIRECT_URI: OnceLock<Regex> = OnceLock::new();
static RE_NUM_NEG: OnceLock<Regex> = OnceLock::new();
static RE_NUM_BIG: OnceLock<Regex> = OnceLock::new();
static RE_DISCOUNT100: OnceLock<Regex> = OnceLock::new();
static RE_PRIV_VAL: OnceLock<Regex> = OnceLock::new();
static RE_TE_VALUE: OnceLock<Regex> = OnceLock::new();
static RE_MAIL_HDR_JSON: OnceLock<Regex> = OnceLock::new();
static RE_KEYWORD_SMUGGLE: OnceLock<Regex> = OnceLock::new();
static RE_B64_XML_SAML: OnceLock<Regex> = OnceLock::new();
static RE_BRAND_HOST: OnceLock<Regex> = OnceLock::new();
static RE_CYR_BRAND: OnceLock<Regex> = OnceLock::new();
static RE_PARAM_PAIR: OnceLock<Regex> = OnceLock::new();
static RE_MIXED_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_CMS_VULN_SLUG: OnceLock<Regex> = OnceLock::new();
static RE_MAGIC_HASH: OnceLock<Regex> = OnceLock::new();
static RE_HEX_NUM: OnceLock<Regex> = OnceLock::new();
static RE_BRACKET_PARAM: OnceLock<Regex> = OnceLock::new();
static RE_PRIV_LIKE_VALUE: OnceLock<Regex> = OnceLock::new();
static RE_PROTO_LINE: OnceLock<Regex> = OnceLock::new();
static RE_INLINE_PROTO: OnceLock<Regex> = OnceLock::new();
static RE_INTERNAL_HOST: OnceLock<Regex> = OnceLock::new();
static RE_SCI_NUM: OnceLock<Regex> = OnceLock::new();
static RE_FORM_BODY: OnceLock<Regex> = OnceLock::new();
static RE_MGMT_ENDPOINT: OnceLock<Regex> = OnceLock::new();
static RE_PARAM_PAIR_WIDE: OnceLock<Regex> = OnceLock::new();
static RE_NUM_TINY: OnceLock<Regex> = OnceLock::new();
static RE_APPLIANCE_CVE: OnceLock<Regex> = OnceLock::new();
static RE_JAVA_ATTACK: OnceLock<Regex> = OnceLock::new();
static RE_SQL_EXTENDED: OnceLock<Regex> = OnceLock::new();
static RE_SQL_TAUTOLOGY: OnceLock<Regex> = OnceLock::new();
static RE_ORM_LOOKUP: OnceLock<Regex> = OnceLock::new();
static RE_RCE_EXTENDED: OnceLock<Regex> = OnceLock::new();
static RE_METHOD_OVERRIDE_PARAM: OnceLock<Regex> = OnceLock::new();
static RE_PHP_DANGER: OnceLock<Regex> = OnceLock::new();
static RE_PHP_VAR_SHAPE: OnceLock<Regex> = OnceLock::new();
static RE_NODEJS_ABUSE: OnceLock<Regex> = OnceLock::new();
static RE_XSS_EXTENDED: OnceLock<Regex> = OnceLock::new();
static RE_LFI_EXTENDED: OnceLock<Regex> = OnceLock::new();
static RE_IIS_LT: OnceLock<Regex> = OnceLock::new();
static RE_IIS_GT: OnceLock<Regex> = OnceLock::new();
static RE_IIS_SQUOTE: OnceLock<Regex> = OnceLock::new();
static RE_IIS_DQUOTE: OnceLock<Regex> = OnceLock::new();
static RE_IIS_GUILLEMET_L: OnceLock<Regex> = OnceLock::new();
static RE_IIS_GUILLEMET_R: OnceLock<Regex> = OnceLock::new();
static RE_RFI_SCHEME: OnceLock<Regex> = OnceLock::new();
static RE_SESSION_URL: OnceLock<Regex> = OnceLock::new();
static RE_BAD_CHARSET: OnceLock<Regex> = OnceLock::new();
static RE_ABS_URI_METHOD: OnceLock<Regex> = OnceLock::new();
static RE_JSON_KEY_SQL: OnceLock<Regex> = OnceLock::new();
static RE_B64_TOKEN: OnceLock<Regex> = OnceLock::new();
static RE_SCRIPT_EXT_HDR: OnceLock<Regex> = OnceLock::new();
static RE_HEX_PAIRS: OnceLock<Regex> = OnceLock::new();
static RE_IPV6_LITERAL: OnceLock<Regex> = OnceLock::new();
static RE_LOCALHOST_DNS: OnceLock<Regex> = OnceLock::new();
static RE_PHP_INI_KEY: OnceLock<Regex> = OnceLock::new();
static RE_JAVA_GADGET: OnceLock<Regex> = OnceLock::new();
static RE_JAVA_SINK: OnceLock<Regex> = OnceLock::new();
static RE_DATA_URI_MARKUP: OnceLock<Regex> = OnceLock::new();
static RE_MULTIPART_BAD_FN: OnceLock<Regex> = OnceLock::new();
static RE_NESTED_PARAM: OnceLock<Regex> = OnceLock::new();
static RE_OCTAL_IP: OnceLock<Regex> = OnceLock::new();
static RE_ENTITY_NAME: OnceLock<Regex> = OnceLock::new();
static RE_SQL_ERROR_MSG: OnceLock<Regex> = OnceLock::new();
static RE_CRLF_HEADER: OnceLock<Regex> = OnceLock::new();
static RE_CRLF_PARAM: OnceLock<Regex> = OnceLock::new();
static RE_TEMPLATE_DIR: OnceLock<Regex> = OnceLock::new();
static RE_PHP_INI_ASSIGN: OnceLock<Regex> = OnceLock::new();
static RE_SENSITIVE_FILE: OnceLock<Regex> = OnceLock::new();
static RE_ERROR_REFLECT: OnceLock<Regex> = OnceLock::new();
static RE_CRED_QUERY: OnceLock<Regex> = OnceLock::new();
static RE_IPV6_URL: OnceLock<Regex> = OnceLock::new();

fn init_regexes() {
    let _ = RE_TAUT_PAIR.get_or_init(|| {
        // `||` is a logical OR in MySQL unless PIPES_AS_CONCAT is enabled.
        Regex::new(r#"(?i)(?:or|and|\|\|)(?:\s+|[(]+)['"]?([a-zA-Z0-9_-]+)['"]?\s*(?:=|\blike\b)\s*['"]?([a-zA-Z0-9_-]+)['"]?[)]*"#).unwrap()
    });
    let _ = RE_TAUT_STATIC.get_or_init(|| {
        vec![
            Regex::new(r#"(?i)(?:or|and|\|\|)(?:\s+|[(]+)1\s*=\s*1[)]*"#).unwrap(),
            Regex::new(r#"(?i)(?:or|and|\|\|)(?:\s+|[(]+)true\b"#).unwrap(),
            Regex::new(r#"(?i)admin'--"#).unwrap(),
            Regex::new(r#"(?i)['"]\s*or\s*['"]"#).unwrap(),
        ]
    });
    let _ = RE_UNION_SELECT.get_or_init(|| {
        Regex::new(r#"(?i)\bunion(?:\s+|/\*.*?\*/|[(])+(?:all(?:\s+|/\*.*?\*/|[(])+)?select\b"#)
            .unwrap()
    });
    let _ = RE_SQL_SLEEP.get_or_init(|| {
        // waitfor delay takes a string literal, not parentheses; the rest are calls.
        Regex::new(r#"(?i)\bwaitfor\s+delay\b|\b(?:sleep|benchmark|pg_sleep)\s*\("#).unwrap()
    });
    let _ = RE_STACKED_DDL.get_or_init(|| {
        Regex::new(r#"(?i)(?:;|\bunion\b).*?\b(?:drop\s+(?:table|database|user|index|view|procedure|function|trigger)|truncate\s+table|alter\s+table|insert\s+into|delete\s+from|create\s+(?:user|database|table|index|view|procedure|function|trigger)|grant\b|revoke\b|handler\s+\w+\s+(?:open|read|close)|call\s+\w+|do\s+\w+|exec\b|execute\b|openrowset|opendatasource|openquery|xp_\w+|sp_oa\w+|sp_addextendedproc|bulk\s+insert|json_table|get_lock|json_value|json_query|openjson)\b"#).unwrap()
    });
    let _ = RE_XSS_SCRIPT.get_or_init(|| {
        // The leading `<` alternative was removed: it turned every closing </script>
        // into an XSS match and blocked legitimate script includes.
        Regex::new(
            r#"(?is)<\s*script[^>]*>.*?(?:alert|eval|document|window|fetch|prompt|location)"#,
        )
        .unwrap()
    });
    let _ = RE_XSS_REMOTE_SCRIPT.get_or_init(|| {
        // Remote HTTPS includes are common in CMS content; plain HTTP and protocol-relative
        // includes are flagged. Local relative paths are allowed.
        Regex::new(r#"(?is)<\s*script\b[^>]*\bsrc\s*=\s*['"]?\s*(?:http://|//)"#).unwrap()
    });
    let _ = RE_XSS_EVENT.get_or_init(|| {
        Regex::new(r#"(?i)<\s*[a-z0-9_-]+[^>]*[\s/]on[a-z]+\s*=\s*['"]?[^'">]+"#).unwrap()
    });
    let _ = RE_XSS_JS_URI.get_or_init(|| {
        // Only executable data documents are flagged; image/font data URIs are benign.
        // image/svg+xml data URIs are inert in <img>/CSS contexts (scripts only run
        // when the SVG is loaded as a document); <svg onload> is covered separately.
        Regex::new(r#"(?i)(?:javascript|vbscript|mocha|feed|livescript):[^\s'"]+|data:(?:text/html|application/xhtml\+xml|text/javascript)[^\s'"]*"#).unwrap()
    });
    let _ = RE_XSS_SVG.get_or_init(|| Regex::new(r#"(?i)<\s*svg[\s/]+onload\s*="#).unwrap());
    let _ = RE_SHELL_CHAIN.get_or_init(|| {
        // `${IFS}` is a whitespace substitute used to bypass naive shell filters.
        Regex::new(r#"(?i)(?:;|\|\||\||&&|[\r\n]+|`|\$\([^)]+\))(?:\s|\$\{?IFS\}?)*(?:cat|bash|curl|wget|nc|whoami|id|sh|powershell|cmd\.exe|netstat|uname|python[0-9.]*|perl|php|ruby|node)\b"#).unwrap()
    });
    let _ = RE_BASE64_DECODE.get_or_init(|| {
        // `base64` alone is common in data URIs; only flag the decoder invocation.
        Regex::new(r#"(?i)(?:;|&&|\|\||\||[\r\n])\s*base64\s+(?:-d|--decode|-D)\b"#).unwrap()
    });
    let _ = RE_POWERSHELL_EXEC.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:powershell(?:\.exe)?|pwsh)\s+(?:-(?:nop|noprofile|enc|encodedcommand|command|executionpolicy|w|windowstyle)\b|/(?:c|k)\b)|\bcmd(?:\.exe)?\s+(?:/\w+\s+)*\/c\b"#).unwrap()
    });
    let _ = RE_SUBSHELL.get_or_init(|| Regex::new(r#"(?i)(?:`[^`]+`|\$\([^)]+\))"#).unwrap());
    let _ = RE_DYNAMIC_EVAL.get_or_init(|| {
        // No trailing \b: alternatives ending in `(` are followed by a non-word char.
        Regex::new(r#"(?i)\b(?:os\.system|subprocess\.|eval\(|exec\(|system\s*\(|assert\s*\(|popen\s*\(|proc_open\s*\(|pcntl_exec\s*\(|mail\s*\(|runtime\.getruntime\(\)\.exec|getruntime\(\)\.exec|new\s+processbuilder|processbuilder\s*\(|passthru\(|shell_exec\()"#).unwrap()
    });
    let _ = RE_PATH_TRAVERSAL.get_or_init(|| {
        // Accept backslash targets and collapsed dots (`....//`) used to evade filters.
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|%252e%252e%252f|(?:\.{2,}[/\\])+)(?:.*?(?:etc/passwd|etc/shadow|boot\.ini|windows[/\\]win\.ini|proc/self|winnt[/\\]win\.ini))"#).unwrap()
    });
    let _ = RE_PATH_DIRECT_SYSTEM.get_or_init(|| {
        Regex::new(r#"(?i)(?:/proc/self/(?:environ|cmdline|maps|fd)|/proc/\d+/(?:environ|cmdline|fd)|/dev/(?:fd|stdin|stdout|stderr)(?:/|$|\s|"|')?|/etc/passwd|/etc/shadow|/windows/win\.ini|c:[/\\]boot\.ini|[a-zA-Z]:[/\\](?:windows|winnt|program files)[/\\]|[/\\]win\.ini\b|[/\\]windows[/\\]system32[/\\]|secrets/kubernetes\.io|serviceaccount/token|/var/run/secrets|/run/secrets|/var/log/[^\s"']+|/var/log/[^\s"']*\.log|(?:^|[/\\])(?:access|error|debug|mysql|postgresql|auth|syslog|messages|secure)(?:\.\d+)?\.log\b)"#).unwrap()
    });
    let _ = RE_PATH_DOTS_ONLY.get_or_init(|| {
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|(?:\.{2,}[/\\])+){2,}"#)
            .unwrap()
    });
    let _ = RE_SSRF_CLOUD.get_or_init(|| {
        Regex::new(r#"(?i)(?:https?|gopher|dict|file|ftp|ldap|ldaps|tftp|smb|netdoc|jar|iiop|corba|sftp|nfs|afs)://(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|instance-data|\[fd00:ec2::254\]|2852039166)(?::\d+)?(?:/|$|\?|#)"#).unwrap()
    });
    let _ = RE_SSRF_PRIVATE.get_or_init(|| {
        Regex::new(r#"(?i)(?:https?|gopher|dict|file|ftp|ldap|ldaps|tftp|smb|netdoc|jar|iiop|corba|sftp|nfs|afs)://(?:127\.\d{1,3}(?:\.\d{1,3}){0,2}|localhost|0\.0\.0\.0|\[::\]|\[::1\]|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\[::ffff:127\.0\.0\.1\]|\[::ffff:7f00:1\]|\[::ffff:169\.254\.169\.254\]|\[::ffff:a9fe:a9fe\]|\[(?:fe80|fe90|fea0|feb0|fec0|fed0|fee0|fef0|fc|fd)[0-9a-f:]*\]|2130706433|0x7f000001)(?::\d+)?(?:/|$|\?|#)"#).unwrap()
    });
    let _ = RE_SSRF_PARAM_CONTEXT.get_or_init(|| {
        Regex::new(r#"(?i)(?:^|[^a-z0-9_])(?:url|uri|urls?|host|hostname|redirect|redirect_uri|redirecturl|return|returnurl|next|continue|callback|callbackurl|webhook|hook|webhookurl|target|targeturl|dest|destination|proxy|fetch|src|source|image|img|file|path|domain|endpoint|check|connect|origem|origen|u|to|link|go|redir|feed)\s*['"]?\s*[=:]\s*['"\[\{,]*$"#).unwrap()
    });
    let _ = RE_COMMENT_STRIP.get_or_init(|| Regex::new(r#"/\*.*?\*/"#).unwrap());
    let _ = RE_WORDPRESS_PROBE.get_or_init(|| {
        // Generic index.php/wp.php are NOT WordPress-specific and used to flag ThinkPHP probes
        // as CMS reconnaissance. Keep only unambiguous WordPress paths.
        Regex::new(r#"(?i)(?:/wp-(?:admin|login\.php|includes|content|cron\.php|config\.php)|/wp/v\d+/users(?:/|$|\?)|/wp-json/wp/v\d+/users(?:/|$|\?)|rest_route=/wp/v\d+/users|\?author=\d+|wlwmanifest\.xml|wp-trackback\.php|wp-cron\.php|wp-links-opml\.php|wp-json/oembed|/license\.txt|/readme\.html|wp-mail\.php|wp-comments-post\.php|wp-signup\.php|wp-activate\.php|wp-register\.php|wp-admin/(?:install|upgrade)\.php|author-sitemap\.xml|wp-sitemap\.xml)"#).unwrap()
    });
    let _ = RE_SENSITIVE_EXPOSURE.get_or_init(|| {
        Regex::new(r#"(?i)(?:/\.env(?:\.[a-z0-9_-]+)?|/\.git(?:/|$|\?)|/\.aws(?:/|$|\?)|/\.ssh(?:/|$|\?)|/(?:phpmyadmin|pma|adminer\.php|actuator/(?:env|beans|configprops|heapdump|threaddump|loggers|mappings|scheduledtasks|conditions|caches|sessions|shutdown|restart|pause|resume|features|gateway|jolokia|flyway|liquibase|auditevents|httptrace|httpexchanges|integrationgraph|quartz|startup|security)|swagger-ui|\.svn|\.hg|\.bzr|CVS|META-INF|docker-compose\.ya?ml|Dockerfile|\.dockerignore|dump\.sql|backup\.sql|db\.sql|database\.sql|dump\.sql\.gz|backup\.tar\.gz|site\.tar\.gz|www\.zip|public_html\.zip|backup\.zip|db\.zip|mysql\.sql|data\.sql|web\.config|app\.config|connectionstrings\.config|Web\.(?:Debug|Release)\.config|global\.asax|server-status|server-info|nginx_status|stub_status|fpm-status|balancer-manager|phpinfo(?:\.php)?|info\.php|test\.php|i\.php|phpversion\.php|elmah\.axd|trace\.axd|glimpse\.axd|elmah|glimpse|trace\.axd|ex4004|iisreset\.log|\.npmrc|\.pypirc|\.pgpass|\.my\.cnf|\.mylogin\.cnf|\.dockercfg|\.DS_Store|\.htpasswd|\.htaccess|\.user\.ini|crossdomain\.xml|clientaccesspolicy\.xml|server\.xml|WEB-INF|appsettings[^/]*\.json|terraform\.tfstate|\.tfstate|jolokia|hawtio|jmx-console|web-console|host-manager|manager/[a-z0-9_.-]+|_cat/[a-z0-9_.-]+|_cluster/[a-z0-9_.-]+|_nodes/[a-z0-9_.-]+|_(?:alias|tasks|snapshot|sql|xpack|security|watcher|ml|rollup|transform|slm|ilm|fleet|features)/?|debug/(?:pprof|vars|requests)|shell\.php|c99\.php|r57\.php|wso\.php|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|\.sqlite_history|\.python_history|\.node_repl_history|\.rediscli_history|\.lesshst|\.viminfo|\.wget-hsts|\.bashrc|\.bash_profile|\.zshrc|\.profile|\.gitconfig|\.git-credentials|\.curlrc|\.inputrc|\.selected_editor|\.sudo_as_admin_successful|\.yarnrc|\.netrc|\.gem/credentials|\.cargo/credentials|\.docker/config\.json|\.kube/config|kubeconfig|\.minikube|\.helm|database\.ya?ml|secrets\.ya?ml|credentials\.json|credentials\.ya?ml|service-account\.json|firebase-adminsdk[^/]*\.json|adminsdk[^/]*\.json|key\.json|private-key\.json|client_secret[^/]*\.json|wp-config\.php[~.]|\.idea|\.vscode|\.vs|\.project|\.settings|\.classpath|\.cproject|nbproject|\.gitlab-ci\.yml|Jenkinsfile|\.travis\.yml|\.circleci/|azure-pipelines\.yml|bitbucket-pipelines\.yml|\.drone\.yml|appveyor\.yml|\.buildkite/|cloudbuild\.yaml|\.github/workflows/|values\.yaml|Chart\.yaml|firebase\.json|\.firebaserc|firestore\.rules|storage\.rules|database\.rules\.json|remoteconfig\.template\.json|serverless\.ya?ml|samconfig\.toml|template\.ya?ml|cdk\.json|amplify\.ya?ml|netlify\.toml|vercel\.json|now\.json|app\.yaml|dispatch\.yaml|cron\.yaml|queue\.yaml|datastore/index\.yaml|main\.tf|variables\.tf|outputs\.tf|terraform\.tfvars|backend\.tf|locals\.tf|Pulumi\.yaml|Pulumi\.dev\.yaml|cdktf\.json|unattend\.xml|sysprep\.inf|autounattend\.xml|sysprep\.xml|panther/unattend|solr/admin|kibana/api|consul/v1|vault/v\d+|eureka/apps|services/registry|gateway/routes|hystrix\.stream|turbine\.stream|/[^/]*\.(?:pem|key|p12|pfx|jks|keystore|ppk)$)(?:\?|/|$|\.php|\.axd|\.json|\.ya?ml|\.xml|\.tf|\.tfvars|\.toml|\.rules|\.log|\.txt|\.sql|\.zip|\.tar\.gz|\.pem|\.key|\.p12|\.pfx|\.jks|\.keystore|\.ppk|\s))"#).unwrap()
    });
    let _ = RE_FRAMEWORK_EXPLOIT.get_or_init(|| {
        Regex::new(r#"(?i)(?:\$\{jndi:(?:ldap|rmi|dns|corba|iiop)|\$\{jndi:|\$\{(?:docker|k8s|kubernetes|spring|sys|main|bundle|web|env|lower|upper|date|hostName|ctx|sd|springProfiles|java|os|line|marker|map|jvmrunargs|base64|url|env|sys|docker|k8s|kubernetes|spring|main|bundle|web|hostName|ctx|sd|springProfiles|java|os|line|marker|map|jvmrunargs)[^}]{0,200}\}|#\{T\([a-z0-9_.]+\)|\$\{T\([a-z0-9_.]+\)|class\.module\.classLoader|class\.module\.resources|denyMethodExecution|xwork\.MethodAccessor|%\{#|_ignition/execute-solution|invokefunction&function=call_user_func|eval-stdin\.php|#post_render|#lazy_builder|\[\]\s*=\s*(?:exec|eval|assert|system|passthru|shell_exec|call_user_func|create_function|preg_replace)\b|\$\{\(|!!<tag:yaml\.org|python/object|javax\.script|ScriptEngineManager|URLClassLoader|TemplatesImpl|JdbcRowSetImpl|SnakeYAML|<!--#(?:exec|include|config|echo|printenv|set|if)\b)"#).unwrap()
    });
    let _ = RE_MYSQL_EXEC_COMMENT.get_or_init(|| {
        // /*!50000UNION*/ is executed by MySQL, so its content must be inspected, not stripped.
        Regex::new(r#"/\*![0-9]*\s*([\s\S]*?)\*/"#).unwrap()
    });
    let _ = RE_JNDI_OBFUSCATION
        .get_or_init(|| Regex::new(r#"(?i)\$\{(lower|upper):([^}]*)\}"#).unwrap());
    let _ =
        RE_JNDI_ENV_LOOKUP.get_or_init(|| Regex::new(r#"(?i)\$\{env:[^}]*:-([^}]*)\}"#).unwrap());
    let _ = RE_TAUT_NUMERIC.get_or_init(|| {
        Regex::new(r#"(?i)(?:or|and|\|\|)\s*\(?\s*(\d{1,10})\s*(>=|<=|>|<|!=)\s*(\d{1,10})\s*\)?"#)
            .unwrap()
    });
    let _ = RE_OR_NUMERIC_COMMENT.get_or_init(|| {
        Regex::new(r#"(?i)['"]?\s*(?:or|and|\|\|)\s+\d{1,10}\s*(?:--|#|/\*)"#).unwrap()
    });
    let _ = RE_OVERLONG_DOT
        .get_or_init(|| Regex::new(r#"(?i)%(?:c0|c1)%(?:ae|2e)|%e0%80%ae|%f0%80%80%ae"#).unwrap());
    let _ = RE_OVERLONG_SLASH.get_or_init(|| {
        Regex::new(r#"(?i)%(?:c0|c1)%(?:af|2f|bc)|%e0%80%af|%f0%80%80%af"#).unwrap()
    });
    let _ = RE_OVERLONG_BACKSLASH.get_or_init(|| {
        Regex::new(r#"(?i)%(?:c0|c1)%(?:5c|9c|dc)|%e0%80%9c|%f0%80%80%9c"#).unwrap()
    });
    let _ = RE_IIS_DOT.get_or_init(|| Regex::new(r#"(?i)%uff0e|%u002e"#).unwrap());
    let _ = RE_IIS_SLASH.get_or_init(|| Regex::new(r#"(?i)%u2215|%u002f|%uff0f"#).unwrap());
    let _ = RE_IIS_BACKSLASH.get_or_init(|| Regex::new(r#"(?i)%u2216|%u005c|%uff3c"#).unwrap());
    let _ = RE_IIS_LT.get_or_init(|| {
        // %u2039 = ‹ used as a fake '<' in IIS-unicode XSS probes.
        Regex::new(r#"(?i)%u2039|%u3008|%uff1c"#).unwrap()
    });
    let _ = RE_IIS_GT.get_or_init(|| Regex::new(r#"(?i)%u203a|%u3009|%uff1e"#).unwrap());
    let _ = RE_IIS_SQUOTE.get_or_init(|| {
        // Typographic quotes used as SQL quote substitutes in IIS unicode.
        Regex::new(r#"(?i)%u2018|%u2019|%u02bc|%u02b9"#).unwrap()
    });
    let _ = RE_IIS_DQUOTE.get_or_init(|| Regex::new(r#"(?i)%u201c|%u201d|%u2033|%u2036"#).unwrap());
    let _ = RE_IIS_GUILLEMET_L.get_or_init(|| {
        // « = fake '<' (IIS unicode XSS probes).
        Regex::new(r#"(?i)%u00ab|%u300a|%uff1a"#).unwrap()
    });
    let _ = RE_IIS_GUILLEMET_R.get_or_init(|| Regex::new(r#"(?i)%u00bb|%u300b|%uff1b"#).unwrap());
    let _ = RE_NOSQL_JSON_OP.get_or_init(|| {
        // MongoDB operator keys in JSON position: {"$ne": ...}, {"$where": ...}
        Regex::new(r#""\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|expr|not|mod|all|size|elemMatch|type|options|jsonSchema|text|lookup|function|accumulator|facet|merge|out|group|project|densify|redact|documents|let|graphLookup|unionWith|search|searchMeta|vectorSearch|changeStream|listCollections)"\s*:"#).unwrap()
    });
    let _ = RE_NOSQL_BRACKET_OP.get_or_init(|| {
        // PHP/Express bracket operator injection: email[$ne]=1&clave[$gt]=
        Regex::new(r#"\[\s*\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|expr|not)\s*\]"#)
            .unwrap()
    });
    let _ = RE_SSTI_JINJA.get_or_init(|| {
        // Jinja/Twig/Nunjucks/Tornado delimiters coupled with template engine sinks.
        // Plain {{ }} without a sink stays benign (JS template objects, docs).
        Regex::new(r#"(?s)\{\{[^{}]{0,800}?(?:_self\b|self\.|env\.|request\.|config\.|session\.|cycler|joiner|namespace|lipsum|forName|getRuntime|__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|os\.|subprocess|popen|['"](?:system|exec|eval|passthru|shell_exec|popen|proc_open|assert|create_function|call_user_func)['"]|\|(?:map|filter|reduce)\s*\(|child_process|execSync|mainModule|process\.mainModule|global\.process|constructor\s*\()[^{}]{0,800}?\}\}"#).unwrap()
    });
    let _ = RE_SSTI_FREEMARKER.get_or_init(|| {
        // FreeMarker ${...} expressions invoking Java reflection or template utils.
        Regex::new(r#"(?s)(?:\$\{[^{}]{0,800}?(?:\?new\b|new_interpreter|Execute|\.evaluate\(|forName|getRuntime|\.exec\(|\?api|\?html|\?js_string|\w+\s*\([^)]{0,120}\))[^{}]{0,800}?\}|<#[a-zA-Z]+[^>]{0,400}?(?:\?new\s*\(|freemarker\.template\.utility|\.exec\s*\(|\bExecute\b)[^>]{0,400}?>)"#).unwrap()
    });
    let _ = RE_SSTI_VELOCITY.get_or_init(|| {
        // Velocity directives reaching Java runtime objects (#set($x=$class...)).
        Regex::new(r#"(?i)(?:#(?:set|if|elseif|foreach|evaluate|include|parse|define|macro)\b[^#\n]{0,400}?\$(?:class|runtime|request|session|application|esc|date|math)\b|#(?:evaluate|include|parse|define)\s*\(\s*\$[a-zA-Z_]\w*)"#).unwrap()
    });
    let _ = RE_CRLF_RESPONSE_HDR.get_or_init(|| {
        // CRLF followed by a response-header name. Multipart request bodies carry
        // Content-Type/Content-Disposition legitimately, so those are excluded.
        Regex::new(r#"(?i)(?:\r\n|\r|\n)[ \t]*(?:(?:set-cookie|location|refresh|www-authenticate|content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|x-xss-protection|server|x-powered-by|x-aspnet[a-z-]*|x-generator|content-length|etag|last-modified|cache-control|bcc|cc|to|from|reply-to|resent-[a-z]+|sender|return-path|subject|x-mailer|x-priority|importance|message-id|in-reply-to|references|mime-version|content-transfer-encoding|x-envelope-[a-z]+|x-original-to|x-sender|x-recipients|errors-to|disposition-notification-to|envelope-to|x-failed-recipients|x-complaints-to|return-receipt-to|x-autoreply|x-autorespond|x-autoresponse|x-autoresponder|list-unsubscribe|list-help|list-post|list-owner|list-subscribe|precedence|x-msmail-priority|x-gm-thrid|x-gm-message-state|x-google-smtp-source|x-receipt|x-verified|x-original-authentication-results|authentication-results|arc-message-signature|dkim-signature|received-spf|x-spam|x-virus|x-barracuda|x-proofpoint|x-messagelab|x-campaign|x-mailgun|x-sendgrid|x-postmark|x-ses|x-mandrill|x-sparkpost|x-mailchimp|x-originating-ip|x-originating-email|x-evidence|x-hashtags|x-social|x-groups|x-complaints|x-abuse|x-notice|x-warning|x-error|x-failure|x-status|x-result|x-response|x-request|x-reply|x-forward|x-resent|apparently-to|delivered-to|x-actual-recipient|original-recipient|final-recipient|reporting-mta|x-qa|x-dsn|x-bounce|x-failed|x-accel-redirect|x-sendfile|x-lighttpd-redirect|x-rewrite-url|x-original-url)[ \t]*:|HTTP/\d(?:\.\d)?\s+\d{3})"#).unwrap()
    });
    let _ = RE_UPLOAD_FILENAME.get_or_init(|| {
        // filename= parameter pointing at an executable/server-parsed extension
        // or Apache override files (.htaccess, .user.ini).
        Regex::new(r#"(?i)(?:file_?name|filename|filepath|upload_?file|attachment_?name)\s*=\s*["']?[^"'\s&;]*?(?:\.(?:php[0-9]?|phtml|phar|asp|aspx|ashx|jsp|jspx|cgi|pl|shtml?|cfm|cfc|cdx|asa|ini|docm|xlsm|pptm|dotm|xltm|xlam|ppsm|potm|sldm|xlsb|docb|xlwb|hta|vbs|wsf|ps1)\b|\.htaccess\b|\.user\.ini\b)"#).unwrap()
    });
    let _ = RE_UPLOAD_CTX.get_or_init(|| {
        Regex::new(r#"(?i)(?:filename|content|file|upload|attach|multipart)"#).unwrap()
    });
    let _ = RE_SERVER_SIDE_TAG.get_or_init(|| {
        // Server-side script open tags: PHP (<?php, <?=), ASP (<%...), JSP (<%=).
        // <?xml is deliberately excluded.
        Regex::new(r#"<\?(?:php\b|=)|<%[@=a-zA-Z]|<cf[a-z]|<cfscript"#).unwrap()
    });
    let _ = RE_SSRF_ALT_TARGET.get_or_init(|| {
        // Loopback expressed as 0, hex or octal; DNS-rebinding wildcard domains.
        Regex::new(r#"(?i)(?:https?|gopher|dict|file|ftp)://(?:0(?::\d+)?(?:/|$|\?)|0x[0-9a-f]{1,8}(?::\d+)?(?:/|$|\?)|0[0-7]{1,3}(?:\.[0-7]{1,3}){3}(?::\d+)?(?:/|$|\?)|(?:[0-9a-z-]+(?:\.[0-9a-z-]+)*\.)?(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me|vcap\.me|localdomain\.com|127\.0\.0\.1\.nip\.io)(?::\d+)?(?:/|$|\?))"#).unwrap()
    });
    let _ = RE_SSRF_INTERNAL_TLD.get_or_init(|| {
        // Internal-only TLDs reachable through URL-shaped parameters.
        Regex::new(r#"(?i)(?:(?:https?|gopher|dict|file|ftp)://[a-z0-9][a-z0-9.-]*\.(?:local|internal|lan|corp|home|intranet|svc|consul|cluster\.local|home\.arpa)(?::\d+)?(?:/|$|\?)|(?:https?|gopher|dict|file|ftp)://(?:metadata|instance-data|kubernetes|docker)(?::\d+)?(?:/|$|\?))"#).unwrap()
    });
    let _ = RE_WIN_SHELL_BINARY.get_or_init(|| {
        // Windows-native post-exploitation binaries and commands.
        Regex::new(r#"(?i)\b(?:net\s+(?:user|localgroup|view|share|group|accounts|stat|time|use|session|config|stop|start)|ipconfig|tasklist|systeminfo|qwinsta|quser|nltest|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|wmic|vssadmin|bcdedit|netsh|reg\s+(?:add|query|delete|import)|arp\s+-a|route\s+print|netstat)(?:\s|$|[|&;),])"#).unwrap()
    });
    let _ = RE_SHELL_METACHAR_GATE
        .get_or_init(|| Regex::new(r#"(?:;|&&|\|\||\||&\s|`|\$\(|[\r\n])"#).unwrap());
    let _ = RE_SQL_ERROR_FUNC.get_or_init(|| {
        // Error-based / blind / file-write SQL primitives beyond UNION SELECT.
        Regex::new(r#"(?i)\b(?:extractvalue|updatexml|exp|floor|rand|name_const|make_set|procedure\s+analyse|load_file|json_keys|json_extract|gtid_subset|gtid_subtract|jsonb_path_query|get_lock|json_table|json_value|json_query|openjson|xp_\w+|openrowset|opendatasource|openquery|sp_oa\w+|sp_addextendedproc|bulk\s+insert|handler\s+\w+)\s*\(|\bwaitfor\s+delay\b|\binto\s+(?:out|dump)file\b"#).unwrap()
    });
    let _ = RE_PHP_WRAPPER.get_or_init(|| {
        // PHP stream wrappers abused for command exec or arbitrary file read.
        Regex::new(
            r#"(?i)\b(?:expect|php|glob|phar|zip|ogg|rar|ssh2\.(?:exec|shell|tunnel|sftp))://"#,
        )
        .unwrap()
    });
    let _ = RE_SHELLSHOCK.get_or_init(|| {
        // Bash function export injection: () { :;}; <command>
        Regex::new(r#"(?i)\(\)\s*\{[^}\n]{0,120}\}\s*;"#).unwrap()
    });
    let _ = RE_PATH_BINARY.get_or_init(|| {
        // Absolute-path binaries (/bin/sh, /usr/bin/curl) and busybox applets
        // behind a shell metacharacter.
        Regex::new(r#"(?i)(?:/|\b)(?:usr/)?(?:bin|sbin|local/bin)/[a-z0-9][a-z0-9._-]*|\bbusybox\s+[a-z0-9._-]+|/dev/(?:tcp|udp)/[\d.a-fA-F:]+/\d+"#).unwrap()
    });
    let _ = RE_XXE_ENTITY.get_or_init(|| {
        // External/parameter entities reaching SYSTEM or PUBLIC identifiers.
        Regex::new(r#"(?i)<!ENTITY[^>]{0,300}?(?:SYSTEM|PUBLIC)\s*["']|<!DOCTYPE[^>]{0,400}?<!ENTITY|<!DOCTYPE\s+[\w:.-]+\s+(?:SYSTEM|PUBLIC)\s*["'][^"']{0,300}?["']"#).unwrap()
    });
    let _ = RE_HEX_BLOB.get_or_init(|| {
        // Long 0x-prefixed hex literals that may carry encoded SQL text.
        Regex::new(r#"(?i)\b0x[0-9a-f]{16,}\b"#).unwrap()
    });
    let _ = RE_JNDI_CHAR_EXTRACT.get_or_init(|| {
        // Log4j char-extraction obfuscation: ${::-j}${::-n}${::-d}${::-i} -> jndi
        Regex::new(r#"\$\{::-([a-zA-Z0-9])\}"#).unwrap()
    });
    let _ = RE_JNDI_DATE_LOOKUP.get_or_init(|| {
        // Log4j date-lookup obfuscation: ${date:'j'} -> j
        Regex::new(r#"\$\{date:'(.)'\}"#).unwrap()
    });

    // --- Injection coverage islands (v3) ---

    // UNION ... SELECT with optional /* */ comments between any letters
    // (`UN/**/ION/**/SEL/**/ECT`). Built programmatically since the pattern is
    // per-letter repetitive.
    let _ = RE_UNION_SELECT_OBF.get_or_init(|| {
        let kw = |word: &str| -> String {
            word.chars()
                .map(|c| format!("{}(?:/\\*.*?\\*/)?", c))
                .collect::<Vec<_>>()
                .join("")
        };
        let pat = format!(
            r"(?i)\b{}(?:\s|/\*.*?\*/|\(+)+(?:{}(?:\s|/\*.*?\*/|\()+)?{}(?:\s|/\*.*?\*/|\()+?\b",
            kw("union"),
            kw("all"),
            kw("select")
        );
        Regex::new(&pat).unwrap()
    });
    let _ = RE_SQL_SUBQUERY.get_or_init(|| {
        // Quote-free subquery injection: =(SELECT ... FROM ...), ' AND (SELECT ...)
        Regex::new(r#"(?i)(?:'|")?\s*(?:\bAND\b|\bOR\b|\bXOR\b|=\s*\(|\(|\bWHERE\b|\bHAVING\b|\bORDER\s+BY\b|\bGROUP\s+BY\b|\bSET\b|\bVALUES\b|\bIN\b|\bBETWEEN\b|\bRLIKE\b|\bREGEXP\b|\bLIKE\b)\s*\(?\s*SELECT\s+.{0,300}?(?:\bFROM\b|\))"#).unwrap()
    });
    let _ = RE_SQL_CASE_HAVING.get_or_init(|| {
        // Blind ORDER BY/CASE and HAVING tautologies without UNION.
        Regex::new(r#"(?i)\bCASE\s+WHEN\s*\([^)]{0,120}\)\s*THEN\b[^;]{0,300}?\bELSE\b|(?:'|")\s*HAVING\s+[\w'"]|\bHAVING\s+\d+\s*(?:=|!=|<|>|<=|>=)"#).unwrap()
    });
    let _ = RE_CMD_IFS_BINARY.get_or_init(|| {
        // Command binary glued to ${IFS}/$IFS whitespace substitution.
        Regex::new(r#"(?i)\b(?:ls|cat|id|whoami|uname|pwd|env|printenv|wget|curl|nc|ncat|netcat|bash|sh|dash|zsh|php|python[0-9.]*|perl|ruby|node|find|xargs|awk|sed|chmod|chown|rm|mv|cp|tar|zip|unzip|base64|openssl|ssh|scp|ftp|tftp|telnet|ping|traceroute|nslookup|dig|host|arp|ifconfig|route|iptables|sudo|mount|umount|dd|ps|top|kill|killall|crontab|nohup|which|whereis|locate|make|gcc|cc|strings|head|tail|sort|uniq|grep|egrep|fgrep|wc|date|source|eval|exec)\s*\$\{?IFS\}?"#).unwrap()
    });
    let _ = RE_SSTI_ARITH.get_or_init(|| {
        // Delimited arithmetic probes: {{7*7}}, ${7*7}, <%=7*7%>, #{7*7}, *{7*7}
        Regex::new(r#"(?i)(?:\{\{|\$\{?|<%=?|#\{|\*\{)\s*\d{1,6}\s*[-+*/%]\s*\d{1,6}\s*(?:\}\}?|%>?|\*\})?"#).unwrap()
    });
    let _ = RE_SSTI_EMBEDDED.get_or_init(|| {
        // ERB/EJS/JSP-style executable tags: <%= system("id") %>, <% Runtime...
        Regex::new(r#"<%\s*[=\-]?\s*(?:eval|exec|system|require|include|load|spawn|`|Runtime|ProcessBuilder|new\s+[A-Z]|javax\.script|ScriptEngine|getRuntime)"#).unwrap()
    });
    let _ = RE_SSTI_EXPR_PARAM.get_or_init(|| {
        // Bare arithmetic in an expression-named parameter: expr=7*7, calc=2+2
        Regex::new(r#"(?i)(?:^|[?&\s"'{(,])(?:expr|eval|template|tpl|view|render|calc|formula|expression|engine|preview|compile|callback|handler)\s*[=:]\s*["']?\s*\d{1,6}\s*[-+*/%]\s*\d{1,6}\s*(?:&|$|\s|"|'|\)|\}|,|;)"#).unwrap()
    });
    let _ = RE_SSRF_USERINFO.get_or_init(|| {
        // http://evil.com@127.0.0.1/ — credentials smuggle the real host after @
        Regex::new(r#"(?i)(?:https?|gopher|dict|file|ftp)://[^/\s'"@]*@(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0|localhost|\[::)"#).unwrap()
    });
    let _ = RE_SSRF_SCHEME_REL.get_or_init(|| {
        // Scheme-relative URL //127.0.0.1:8080/ (the char before // must not be ':')
        Regex::new(r#"(?i)//(?:127\.\d{1,3}(?:\.\d{1,3}){0,2}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[::1\])(?::\d+)?(?:/|$|\?)"#).unwrap()
    });
    let _ = RE_LDAP_META.get_or_init(|| {
        // LDAP filter metacharacters: *)( , )(| , (=*) , *)(
        Regex::new(r#"(?i)\)\s*\(\s*[|&*!]|=\s*\*\s*\)|\(\s*[|&]\s*\(|\*\s*\)\s*\(|(?:^|[?&\s"'(,])(?:user|uid|login|username|cn|samaccountname|mail|dn|telephonenumber|telephone|mobile|pager|roomnumber|secretary|manager|directreports|seealso|usercertificate|usersmimecertificate|userpkcs12|audio|businesscategory|carlicense|departmentnumber|employeenumber|employeetype|facsimiletelephonenumber|homephone|homepostaladdress|initials|jpegphoto|labeleduri|physicaldeliveryofficename|postaladdress|postalcode|preferredlanguage|registeredaddress|sn|st|street|title|distinguishedname|memberof|ou)\s*=\s*\*+"#).unwrap()
    });
    let _ = RE_DESERIALIZATION.get_or_init(|| {
        // Java (rO0AB = base64 AC ED 00 05), PHP object (O:8:"Class":...) and
        // array (a:2:{i:0;...}) serialization, .NET ViewState (/wEP...) and
        // BinaryFormatter (AAEAAAD) markers.
        Regex::new(r#"(?i)\brO0AB[A-Za-z0-9+/=]{8,}|\bO:\d+:"[A-Za-z_\\]{1,64}":\d+:\{|\ba:\d+:\{|/wE[PD][A-Za-z0-9+/=]{16,}|\bAAEAAAD[A-Za-z0-9+/=]{8,}|\baced[0-9a-fA-F]{4}\b|\bH4sI[A-Za-z0-9+/=]{4,}|_\$\$ND_FUNC\$\$|\bC:\+?\d+:"[A-Za-z_\\]{1,64}":\d+:\{|\bS:\+?\d+:"|__PHP_Incomplete_Class|\b(?:cos|posix|nt|os|subprocess|c__builtin__|__builtin__|copy_reg|pickle|dill|shelve|joblib|marshal|numpy|pandas|torch|tensorflow)\r?\n(?:system|exec|eval|popen|spawn|call|run|Popen|check_output|getoutput|getstatusoutput|loads|dumps|save|load)\r?\n"#).unwrap()
    });
    let _ = RE_PHP_FUNC_CALLBACK.get_or_init(|| {
        // PHP higher-order functions invoked with a dangerous callable name.
        Regex::new(r#"(?i)\b(?:array_map|array_filter|usort|uasort|uksort|array_reduce|call_user_func|call_user_func_array|call_user_method|call_user_method_array|forward_static_call|forward_static_call_array|register_shutdown_function|register_tick_function|set_error_handler|spl_autoload_register|iterator_apply|preg_replace_callback|array_walk|array_walk_recursive|mb_ereg_replace|preg_filter|FFI::cdef|ffi::cdef|ReflectionFunction|ReflectionMethod|Closure::fromCallable)\s*\(\s*['"](?:system|exec|shell_exec|passthru|popen|proc_open|assert|eval|create_function)['"]"#).unwrap()
    });
    let _ = RE_PHP_VAR_CALL.get_or_init(|| {
        // Variable-function invocation with a string literal: $f('id'), $f(`id`)
        Regex::new(r#"(?i)\$[a-zA-Z_]\w{0,4}\s*\(\s*['"`][^'"`]{1,60}['"`]\s*\)"#).unwrap()
    });
    let _ = RE_PHP_CONCAT_ASSIGN.get_or_init(|| {
        // $f='sys'.'tem' string-concat obfuscation feeding a later $f(...) call.
        Regex::new(
            r#"(?i)\$[a-zA-Z_]\w*\s*=\s*['"][a-zA-Z_]{2,20}['"]\s*\.\s*['"][a-zA-Z_]{2,20}['"]"#,
        )
        .unwrap()
    });
    let _ = RE_WIN_LOLBIN.get_or_init(|| {
        // Living-off-the-land binaries that are hostile even without a metachar:
        // certutil -decode, bitsadmin /transfer, mshta, rundll32, wmic process call.
        Regex::new(r#"(?i)\b(?:certutil\s+(?:-decode|-encode|-urlcache|-verifyctl)|bitsadmin\s+/|mshta\s+(?:javascript|vbscript|http)|rundll32\s+\w+\s*,|regsvr32\s+/|wmic\s+process\s+call|psexec(?:\.exe)?\s|schtasks\s+/create|at\s+\d{1,2}:\d{2}|msbuild(?:\.exe)?(?:\s|$|[/?&"'<>])|installutil(?:\.exe)?(?:\s|$|[/?&"'<>])|regasm(?:\.exe)?(?:\s|$|[/?&"'<>])|regsvcs(?:\.exe)?(?:\s|$|[/?&"'<>])|msxsl(?:\.exe)?(?:\s|$|[/?&"'<>])|ieexec(?:\.exe)?(?:\s|$|[/?&"'<>])|fodhelper(?:\.exe)?(?:\s|$|[/?&"'<>])|computerdefaults(?:\.exe)?(?:\s|$|[/?&"'<>])|forfiles(?:\.exe)?(?:\s|$|[/?&"'<>])|pcalua(?:\.exe)?(?:\s|$|[/?&"'<>])|sdclt(?:\.exe)?(?:\s|$|[/?&"'<>])|slui(?:\.exe)?(?:\s|$|[/?&"'<>])|wsreset(?:\.exe)?(?:\s|$|[/?&"'<>])|dfsvc(?:\.exe)?(?:\s|$|[/?&"'<>])|desktopimgdownldr(?:\.exe)?(?:\s|$|[/?&"'<>])|syncappvpublishingserver(?:\.exe)?(?:\s|$|[/?&"'<>])|eventvwr(?:\.exe)?\s+[^\s]*\.msc|presentationhost(?:\.exe)?(?:\s|$|[/?&"'<>])|runscripthelper(?:\.exe)?(?:\s|$|[/?&"'<>])|msdt(?:\.exe)?(?:\s|$|[/?&"'<>])|pcwrun(?:\.exe)?(?:\s|$|[/?&"'<>])|xwizard(?:\.exe)?(?:\s|$|[/?&"'<>])|ie4uinit(?:\.exe)?(?:\s|$|[/?&"'<>])|infdefaultinstall(?:\.exe)?(?:\s|$|[/?&"'<>])|gonext(?:\.exe)?(?:\s|$|[/?&"'<>]))"#).unwrap()
    });
    let _ = RE_XPATH_EXPR.get_or_init(|| {
        // XPath location paths and function/predicate probes. Single-segment
        // paths like //user stay benign; two-segment paths, //x(), //x[],
        // //*, (//, quote-or-and //, position()/last() predicates and [@attr=]
        // are flagged.
        Regex::new(r#"(?i)//[a-zA-Z_@*-][\w*-]*(?:/[\w.*-]+)+(?:\[[^\]]{0,120}\])?|//[a-zA-Z_@*-][\w*-]*(?:\(\)|\[[^\]]{0,120}\])|//\*|\(\s*//|['"]\s*(?:or|and)\s+//|\[\s*(?:position|last)\s*\(\s*\)\s*[=\]]|\[\s*@[\w:.-]+\s*="#).unwrap()
    });
    let _ = RE_XPATH_FUNC.get_or_init(|| {
        // XPath function names — fire only when //, ::, or a quote is also
        // present (the conjunction lives in tokenize()).
        // XPath-distinctive names plus the ambiguous-but-real XPath functions
        // id/key/document/text — those get a "."-prefix guard in tokenize()
        // so JS method calls (el.text(), obj.key()) do not fire.
        Regex::new(r#"(?i)\b(?:concat|contains|starts-with|ends-with|substring|substring-before|substring-after|normalize-space|string-length|translate|generate-id|processing-instruction|namespace-uri|local-name|position|last|id|key|document|text)\s*\("#).unwrap()
    });
    let _ = RE_XPATH_AXIS.get_or_init(|| {
        // XPath axis specifiers: ancestor::, attribute::, child::, etc.
        Regex::new(r#"(?i)\b(?:ancestor|ancestor-or-self|attribute|child|descendant|descendant-or-self|following|following-sibling|namespace|parent|preceding|preceding-sibling|self)::"#).unwrap()
    });

    let _ = RE_UNC_PATH.get_or_init(|| {
        // Windows UNC paths: \\host\share and scheme-relative //host.tld/path
        // used as file targets.
        Regex::new(r#"(?i)\\\\[a-z0-9_.-]{1,64}\\[a-z0-9_./\\ -]{0,120}|//[a-z0-9][a-z0-9.-]{0,80}\.[a-z]{2,10}/[a-z0-9_./~%-]{0,120}"#).unwrap()
    });
    let _ = RE_UNC_BENIGN_EXT.get_or_init(|| {
        // A UNC/scheme-relative match ending in a common document, media or
        // archive extension is a file reference, not a payload drop. Executables,
        // scripts, configs and extension-less shares stay hostile.
        Regex::new(r#"(?i)\.(?:xlsx|xls|docx|doc|pdf|csv|pptx|ppt|rtf|odt|ods|odp|txt|png|jpe?g|gif|bmp|webp|svg|mp3|mp4|mov|avi|zip|rar|7z|tar|gz|log)(?:[\s/?&#"')\]},;]|$)"#).unwrap()
    });
    let _ = RE_ADS_PATH.get_or_init(|| {
        // NTFS alternate data streams: file.txt:streamname
        Regex::new(r#"(?i)[a-z0-9_.-]+\.[a-z0-9]{1,10}:[a-z_][a-z0-9_.$-]{2,39}"#).unwrap()
    });
    let _ = RE_CMD_EXEC_TRICK.get_or_init(|| {
        // Config/exec tricks that need no shell metacharacter:
        // sed -e 'e cmd', tar --checkpoint-action, find -exec, git core.pager,
        // awk BEGIN{system}, openssl s_client, telnet host port, whois $var.
        Regex::new(r#"(?i)\bsed\s+-[a-z]*e\b|--checkpoint-action|find\s+[^|]*?-exec\b|core\.pager\s*=|BEGIN\s*\{\s*system|s_client\b|telnet\s+[a-z0-9.-]+\s+\d{2,5}\b|whois\s+\$|nslookup\s+\$|ping\s+-c\d+\s+\$"#).unwrap()
    });
    let _ = RE_NOSQL_ADMIN_CMD.get_or_init(|| {
        // MongoDB diagnostic/admin commands and CouchDB/Elasticsearch/SQL
        // query documents that carry no $ operator.
        Regex::new(r#"(?i)"(?:\$currentOp|buildInfo|serverStatus|whatsmyuri|hostInfo|cpuInfo|diagnosticData|connPoolStats|indexStats|planCacheStats|listSessions|currentOp|collStats|dbStats|top|killOp|killAllOperations|setParameter|getCmdLineOpts|getLog|logRotate|rotateCertificates|replSetGetStatus|replSetGetConfig|listDatabases|listCollections|validate|repairDatabase|setProfilingLevel|fsyncLocked|unlock|lock|applyOps|appendOplogNote|connectionStatus|isMaster|hello|saslStart|saslContinue|createUser|updateUser|dropUser|grantRolesToUser|revokeRolesFromUser|rolesInfo|logout|authenticate|ping|fsync|shutdown|compact)"\s*:|"script"\s*:\s*\{[^}]{0,300}?"source"\s*:"#).unwrap()
    });
    let _ = RE_SQL_JSON_FIELD.get_or_init(|| {
        // SQL statement smuggled inside a JSON string field: {"query":"SELECT ..."}
        Regex::new(r#"(?i)"(?:query|filter|where|sql|statement|command|q|search|criteria|selector|expression|predicate|commandText|cmd)"\s*:\s*"[^"]{0,400}?\b(?:select|insert|update|delete|drop|exec|execute|truncate|alter|create|grant|revoke)\b"#).unwrap()
    });
    let _ = RE_CRLF_ANY_HDR.get_or_init(|| {
        // Strict \r\n followed by any header-shaped token (2-40 chars + ':').
        // Multipart bodies legitimately carry Content-Type/Content-Disposition;
        // those are filtered out in tokenize() when multipart is detected.
        Regex::new(r#"(?i)\r\n[ \t]*[A-Za-z][A-Za-z0-9_-]{1,40}[ \t]*:"#).unwrap()
    });
    let _ = RE_CRLF_CONTENT_HDR.get_or_init(|| {
        // Content-* headers after CRLF — only hostile outside multipart bodies.
        Regex::new(r#"(?i)(?:\r\n|\r|\n)[ \t]*(?:content-type|content-disposition|content-location|content-range|content-md5)[ \t]*:"#).unwrap()
    });
    let _ = RE_EMAIL_ENCODED_WORD.get_or_init(|| {
        // RFC 2047 encoded-word header injection: =?UTF-8?B?...?=
        Regex::new(r#"(?i)=\?(?:utf-?7|x-[a-z0-9-]{1,20}|unknown-8bit)\?[BbQq]\?[^?\s]{2,200}\?="#)
            .unwrap()
    });
    let _ = RE_SSTI_SMARTY.get_or_init(|| {
        // Smarty template tags reaching PHP or file sinks.
        Regex::new(r#"(?i)\{(?:eval|insert|fetch|include|php|ldelim|rdelim)\b[^}\n]{0,300}?\}|\{if\s+[^}\n]{0,200}?(?:phpinfo|system|exec|eval|`)[^}\n]{0,200}?\}"#).unwrap()
    });
    let _ = RE_SSRF_CLOUD_SCHEME.get_or_init(|| {
        // Cloud/exfil-capable URL schemes behind a URL-ish parameter.
        Regex::new(r#"(?i)(?:s3|gs|az|oss|ssh2|nfs|sftp|smb|netdoc|jar|iiop|corba|tftp|ldap|ldaps|gopher|dict|php|expect|zip|phar|glob|rar|ogg|ssh|snews|nntp|news|mid|cid|magnet|bitcoin|chrome|view-source|feed|z39\.50|prospero|wais|imap|pop3|smtp|snmp|rtsp|rtmp|mms)://|jrt:/"#).unwrap()
    });
    let _ = RE_XXE_REF.get_or_init(|| {
        // External references that resolve attacker-controlled resources without
        // a DOCTYPE: xml-stylesheet href, xml:base, xi:include href.
        Regex::new(r#"(?i)(?:xml-stylesheet[^>]{0,300}?href\s*=\s*["']\s*(?:https?|file|php|expect|glob|phar|rar|ogg|ssh2|zip)|xml:base\s*=\s*["']\s*https?://|xi?:?include[^>]{0,300}?href\s*=\s*["']\s*(?:https?|file|php|expect|glob|phar|rar|ogg|ssh2|zip))"#).unwrap()
    });
    let _ = RE_PHP_DOLLAR_BRACE_CALL.get_or_init(|| {
        // Complex variable-function call: ${'_GET'['a']}('id'), ${'sys'.'tem'}('id')
        Regex::new(r#"(?i)\$\{[^}\n]{1,120}\}\s*\(|\$\{[^}\n]{1,120}?\(\s*['"`][^'"`]{1,60}['"`]\s*\)[^}\n]{0,60}?\}"#).unwrap()
    });
    let _ = RE_PHP_EVAL_MODIFIER.get_or_init(|| {
        // preg_replace/preg_filter/mb_ereg_replace with the 'e' (eval) modifier.
        Regex::new(
            r#"(?i)\b(?:mb_ereg_replace|preg_replace|preg_filter)\s*\([^)]{0,200}?,\s*['"]e['"]"#,
        )
        .unwrap()
    });
    let _ = RE_NOSQL_DB_PATH.get_or_init(|| {
        // CouchDB/Elasticsearch/Mongo data-plane endpoints in the path.
        Regex::new(r#"(?i)/(?:_all_docs|_find|_search|_bulk|_sql|_xpack|_alias|_tasks|_snapshot|_security|_watcher|_ml|_rollup|_transform|_slm|_ilm|_fleet|_features)(?:/|\?|&|$|\s)"#).unwrap()
    });
    let _ = RE_PHP_GADGET_CLASS.get_or_init(|| {
        // PHP unserialize gadget classes reachable via iterator/object APIs.
        Regex::new(r#"(?i)\b(?:RecursiveArrayIterator|RecursiveIteratorIterator|SplFileObject|SplTempFileObject|FilesystemIterator|RecursiveDirectoryIterator|GlobIterator|SplObjectStorage|ArrayObject|ArrayIterator)\s*\("#).unwrap()
    });
    // ---- v6 protocol/semantic layer ----
    let _ = RE_NESTED_QUANT.get_or_init(|| {
        // ReDoS shape: quantifier or ambiguous alternation inside a group that
        // itself carries an outer quantifier: (a+)+, (.*)*, (a|a)*, ([a-z]+)*
        Regex::new(r#"\([^()\n]{1,80}(?:[+*]|\|)[^()\n]{0,80}\)\s*(?:[+*]|\{\d)"#).unwrap()
    });
    let _ = RE_CSV_FORMULA.get_or_init(|| {
        // Spreadsheet formula injection at the start of a cell value.
        Regex::new(r#"(?i)["'\s,=](?:cmd\||powershell|importxml|hyperlink|sum\s*\(|evaluate\s*\(|exec\s*\(|[+\-@]\s*[A-Za-z0-9(])"#).unwrap()
    });
    let _ = RE_LOG_LINE.get_or_init(|| {
        // Forged log line: real or JSON-escaped newline followed by a
        // timestamped level, bracketed level, or forged separator banner.
        // JSON bodies carry literal \n (backslash-n), so both forms match.
        Regex::new(r#"(?:\r\n|\r|\n|\\r\\n|\\n|\\r)\s*\[?\s*(?:\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?|\d{4}-\d{2}-\d{2}[\s\]]+(?:INFO|ERROR|WARN(?:ING)?|DEBUG|TRACE|FATAL|CRITICAL|NOTICE|ALERT|EMERG)|INFO|ERROR|WARN(?:ING)?|DEBUG|TRACE|FATAL|CRITICAL|NOTICE|ALERT|EMERG|panic|fatal)\b|(?:\r\n|\r|\n|\\r\\n|\\n|\\r)\s*(?:\s*at\s+[\w.$]+\s*\(|-{2,}\s*(?:SYSTEM|ADMIN|ROOT|ALERT|WARNING|ERROR|INFO|DEBUG))"#).unwrap()
    });
    let _ = RE_SAML_PROTO.get_or_init(|| {
        // SAML protocol markers: unsigned assertions/responses are the attack surface.
        Regex::new(r#"(?i)samlp?:[A-Za-z]|SAMLResponse=|SAMLRequest=|\bSAML(?:Request|Response)\s*:|saml:Assertion|samlp:Response"#).unwrap()
    });
    let _ = RE_XSLT.get_or_init(|| {
        Regex::new(r#"<xsl:(?:stylesheet|transform|value-of|apply-imports|include|import|copy-of)"#)
            .unwrap()
    });
    let _ = RE_XQUERY.get_or_init(|| {
        Regex::new(r#"\b(?:declare\s+(?:variable|function)\s+\$|for\s+\$\w+\s+in\b|collection\s*\(|fn:doc\s*\(|doc\s*\(\s*["'](?:file:|https?:))"#).unwrap()
    });
    let _ = RE_SMTP_CMD.get_or_init(|| {
        // Raw SMTP verbs at line start inside a request body.
        Regex::new(r#"(?im)^\s*(?:EHLO|HELO|MAIL\s+FROM|RCPT\s+TO|DATA|VRFY|EXPN|AUTH|QUIT|RSET|NOOP|STARTTLS)\b[ :<]"#).unwrap()
    });
    let _ = RE_JSONRPC_EXEC.get_or_init(|| {
        // JSON-RPC / RPC-style method dispatch to dangerous primitives.
        Regex::new(r#"["']?(?:method|action|command|cmd|func|function)["']?\s*:\s*["'](?:system|exec|shell|cmd|passthru|eval|popen|call_user_func|proc_open|assert)[."']"#).unwrap()
    });
    let _ = RE_ABS_UPLOAD_PATH.get_or_init(|| {
        // filename= pointing at an absolute server path (archive slip vector).
        Regex::new(r#"(?i)filename\s*=\s*["']?(?:/etc/|/var/|/tmp/|/usr/|/bin/|/sbin/|/opt/|/root/|/home/|/proc/|/sys/|[a-zA-Z]:[\\/])"#).unwrap()
    });
    let _ = RE_NUMERIC_ANOMALY.get_or_init(|| {
        // Numeric fields whose value is a signed/decimal token (checked in code).
        Regex::new(r#"["']?(?:qty|quantity|price|amount|bid|total|weight|score|bonus|discount(?:_percent)?|balance|seats|quota)["']?\s*[:=]\s*-?\d"#).unwrap()
    });
    let _ = RE_PRIVILEGED_KEY.get_or_init(|| {
        // Privileged JSON keys (value checked in code to stay conservative).
        Regex::new(r#"["']?(?:role|isadmin|is_admin|admin|permissions?|owner_?id|verified|moderated|approved|is_staff|admin_override|group|account_?type|billing|features|debug|shell)["']?\s*:"#).unwrap()
    });
    let _ = RE_WEBASSET_EXT.get_or_init(|| {
        Regex::new(r#"(?i)\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3|wav|pdf|txt|xml|json)$"#).unwrap()
    });
    let _ = RE_ACCT_PATH.get_or_init(|| {
        Regex::new(r#"(?i)/(?:account|profile|settings|user|admin|dashboard|private|secure|billing|orders?|cart|checkout|member)s?/"#).unwrap()
    });
    let _ = RE_REDIRECT_URI
        .get_or_init(|| Regex::new(r#"(?i)redirect_uri\s*=\s*([^&\s"']+)"#).unwrap());
    let _ = RE_NUM_NEG.get_or_init(|| {
        Regex::new(r#"["']?(?:qty|quantity|price|amount|bid|total|weight|score|bonus|discount(?:_percent)?|balance|seats|quota)["']?\s*[:=]\s*-\d"#).unwrap()
    });
    let _ = RE_NUM_BIG.get_or_init(|| {
        // Capture group 1 = the number, so the caller can exempt canonical
        // 32-bit boundary constants (INT32_MAX/UINT32_MAX are legitimate
        // developer test values, unlike arbitrary huge magnitudes).
        Regex::new(r#"["']?(?:qty|quantity|price|amount|bid|total|weight|score|bonus|discount(?:_percent)?|balance|seats|quota)["']?\s*[:=]\s*([1-9]\d{4,}|9\d{3})\b"#).unwrap()
    });
    let _ = RE_NUM_TINY.get_or_init(|| {
        // Denormal-tiny money/quantity values used for rounding exploits.
        Regex::new(r#"["']?(?:qty|quantity|price|amount|bid|total|weight|score|bonus|balance|quota)["']?\s*[:=]\s*0\.0{3,}\d"#).unwrap()
    });
    let _ = RE_DISCOUNT100.get_or_init(|| {
        Regex::new(r#"["']?discount(?:_percent)?["']?\s*[:=]\s*(?:1\d\d|[2-9]\d\d)"#).unwrap()
    });
    let _ = RE_PRIV_VAL.get_or_init(|| {
        Regex::new(r#"(?i)["']?(?:role|group|account_?type)["']?\s*:\s*["']?(?:admin|administrator|root|superuser|owner)\b|["']?(?:isadmin|is_admin|admin|verified|moderated|approved|is_staff|admin_override|debug|shell)["']?\s*:\s*(?:true|1\b)|permissions["']?\s*:\s*\[[^\]]*["']\*|owner_?id["']?\s*:"#).unwrap()
    });
    let _ = RE_TE_VALUE.get_or_init(|| Regex::new(r#"(?i)^\s*chunked\s*$"#).unwrap());
    let _ = RE_MAIL_HDR_JSON.get_or_init(|| {
        // Mail-header keys smuggled inside JSON API payloads.
        Regex::new(r#"(?i)["'](?:received|x-original-to|return-path|errors-to|resent-from|resent-to|delivered-to|x-envelope-from)["']\s*:"#).unwrap()
    });
    let _ = RE_KEYWORD_SMUGGLE.get_or_init(|| {
        // Canonical keywords that only become dangerous AFTER confusable fold —
        // gated on is_obfuscated so plain search text stays benign.
        Regex::new(r#"(?i)\b(?:select[\s+]+[\w*]+[\s+]+from|union[\s+]+(?:all[\s+]+)?select|password|passwd|admin|secret|token|api[_-]?key|credential|shadow|key)\b"#).unwrap()
    });
    let _ = RE_B64_XML_SAML.get_or_init(|| {
        // Base64 blob that decodes to an XML document carrying SAML markers.
        // PD94bWwg = "<?xml "; the SAML namespace survives base64 in several
        // alignments so we match the raw blob against loose fragments.
        Regex::new(r#"[A-Za-z0-9+/=]{200,}"#).unwrap()
    });
    let _ = RE_BRAND_HOST.get_or_init(|| {
        Regex::new(r#"(?i)pple|g00gle|paypa|amaz|neta|micros|faceb|insta|dropb|ebay|walmrt|app1e"#)
            .unwrap()
    });
    let _ = RE_CYR_BRAND.get_or_init(|| Regex::new(r#"аррӏе|раураӏ|googӏe"#).unwrap());
    let _ = RE_PARAM_PAIR.get_or_init(|| {
        // key=value / "key":"value" pairs across query strings and JSON bodies.
        Regex::new(
            r#"(?i)["']?([a-z_][a-z0-9_.\-]{0,40})["']?\s*[:=]\s*["']?([^&\s"',}\]]{1,200})"#,
        )
        .unwrap()
    });
    let _ = RE_MIXED_TOKEN.get_or_init(|| {
        // Alphanumeric tokens blending Latin with Cyrillic/Greek lookalikes.
        Regex::new(r#"[0-9A-Za-z\u{0370}-\u{03FF}\u{0400}-\u{04FF}\u{1C80}-\u{1C8F}]+"#).unwrap()
    });
    let _ = RE_CMS_VULN_SLUG.get_or_init(|| {
        // Historically vulnerable CMS plugin/action slugs (WordPress et al.).
        Regex::new(r#"(?i)revslider|elementor|timthumb|duplicator|wp\.vcd|wp\.vcd|filemanager|wp\.file\.manager|ninja\.forms|ninja-forms|mailpoet|wpdiscuz|responsivevoice|contact\.form.?7|gravityforms|gravity\.forms|wpscan|really\.simple\.ssl|wp\.cron\.php|arbitrary\.file|show_image|image\.php\?|load-scripts|load-styles"#).unwrap()
    });
    let _ = RE_MAGIC_HASH.get_or_init(|| {
        // PHP loose-comparison magic hashes: 0e<digits> == 0 in PHP 7.
        Regex::new(r#"^0e\d{3,}$"#).unwrap()
    });
    let _ = RE_HEX_NUM.get_or_init(|| {
        // Hex/octal-looking numeric juggling values (0x539, 017, 0b101).
        Regex::new(r#"^(?:0x[0-9a-f]+|0b[01]+|0[0-7]{2,})$"#).unwrap()
    });
    let _ = RE_BRACKET_PARAM.get_or_init(|| {
        // PHP/Rails-style array params: key[]=v, key[0]=v, key[sub]=v.
        Regex::new(r#"(?i)["']?([a-z_][a-z0-9_]*)\s*(?:\[\]|\[\d+\]|\[[a-z_][a-z0-9_]*\])["']?\s*[:=]\s*["']?([^&\s"',}\]]{1,120})"#).unwrap()
    });
    let _ = RE_PRIV_LIKE_VALUE.get_or_init(|| {
        // Values that signal privilege/conflict intent in duplicate params.
        Regex::new(r#"(?i)^(?:admin|administrator|root|staff|internal|support|sudo|operator|superuser|moderator|owner|manager|editor|true|yes|on|enabled?|active|verified|approved|debug|test)$"#).unwrap()
    });
    let _ = RE_PROTO_LINE.get_or_init(|| {
        // Redis/Memcached/RESP command at line start (after CRLF smuggling).
        Regex::new(r#"(?im)^\s*(?:set|get|flushall|flush_all|flushdb|config|eval|del|delete|unlink|keys|scan|hscan|sscan|zscan|incr|decr|incrby|decrby|lpush|rpush|lpushx|rpushx|linsert|lpop|rpop|rpoplpush|lrange|lrem|lset|ltrim|llen|lindex|lpos|hset|hsetnx|hmset|hget|hmget|hdel|hexists|hkeys|hlen|hvals|hincrby|hscan|sadd|srem|smove|spop|srandmember|scard|sismember|smembers|sdiff|sinter|sunion|zadd|zrem|zincrby|zrange|zrevrange|zrangebyscore|zrevrangebyscore|zrank|zrevrank|zscore|zcard|zcount|zlexcount|select|auth|expire|pexpire|expireat|persist|ttl|pttl|ping|echo|info|shutdown|slaveof|replicaof|debug|slowlog|client|cluster|migrate|rename|renamenx|sort|save|bgsave|bgrewriteaof|lastsave|monitor|sync|psync|replconf|swapdb|object|memory|xadd|xread|xrange|xlen|xtrim|publish|subscribe|psubscribe|punsubscribe|pubsub|bitcount|bitop|bitpos|getbit|setbit|dump|exists|restore|geoadd|georadius|geosearch|geopos|geodist|geohash|mget|mset|msetnx|pfadd|pfcount|pfmerge|randomkey|asking|readonly|readwrite|failover|reset|append|prepend|cas|gets|gat|touch|stats|version|quit|add|replace|getdel|getex)\b"#).unwrap()
    });
    let _ = RE_INLINE_PROTO.get_or_init(|| {
        // Inline memcached/redis verb at value start (no CRLF needed).
        Regex::new(r#"(?i)^(?:get|set|add|delete|flush_all|flushall|stats|version|quit|prepend|append|cas|gets|gat|touch|incr|decr|replace|gets)\s+\S"#).unwrap()
    });
    let _ = RE_INTERNAL_HOST.get_or_init(|| {
        Regex::new(r#"(?i)(?:169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|metadata\.google\.internal|host\.docker\.internal|kubernetes\.default|instance-data|(?:^|[^a-z0-9])(?:internal|intranet|corp|lan|home)\.)"#).unwrap()
    });
    let _ = RE_SCI_NUM.get_or_init(|| {
        // Scientific-notation magnitudes: |exponent| >= 30 overflows f64/i64.
        Regex::new(r#"(?i)^-?\d+(?:\.\d+)?[eE]([+-]?\d+)$"#).unwrap()
    });
    let _ = RE_FORM_BODY.get_or_init(|| {
        // application/x-www-form-urlencoded shape: key=value&...
        Regex::new(r#"(?i)^[a-zA-Z_][\w.\-]*="#).unwrap()
    });
    let _ = RE_MGMT_ENDPOINT.get_or_init(|| {
        // Management/debug surfaces with no legitimate public exposure.
        Regex::new(r#"(?i)/(?:api/v\d+/namespaces/|containers/json|jolokia|debug/(?:pprof|vars|requests)|_cat/|_cluster/|_nodes/|_all_docs|pprof/|_bulk|_sql\b|_xpack|_tasks|_snapshot|_aliases|_settings|_mapping)"#).unwrap()
    });
    let _ = RE_JAVA_ATTACK.get_or_init(|| {
        // Java runtime namespaces and deserialization/gadget vocabulary that
        // has no legitimate place in an HTTP parameter or JSON/XML body.
        // "@type" alone is JSON-LD schema markup — only flag when the value is
        // a Java-ish class name (fastjson/jackson gadget style).
        Regex::new(r#"(?i)\b(?:java|javax|sun|com\.sun|oracle|ognl|javassist|xstream|fastjson|mvel|spel|groovy|aspectjweaver|beanshell|jython|mozilla\.rhino|org\.omg|org\.apache\.ibatis|com\.mchange|org\.slf4j|ch\.qos|log4j|org\.apache\.logging|org\.eclipse)\.[a-z]|org\.apache\.commons|com\.opensymphony|org\.springframework|com\.thoughtworks|org\.yaml\.snakeyaml|flex\.messaging|org\.jsecurity|com\.alibaba\.fastjson|xwork\.|struts|webwork|rO0AB|"@type"\s*:\s*"[^"]*(?:java|com\.sun|oracle|ognl|xstream|fastjson|javassist|aspectj|beanshell|jython|rhino|groovy|mvel|spel|opensymphony|springframework)|invokertransformer|templatesimpl|jdbcrowsetimpl|jdk\.internal|clonefactory|ognl\.|spel\.|mvel\.|#\{[a-zA-Z_]|\$\{[a-zA-Z_]+\.(?:get|set|eval|exec|runtime|process|class|forname|newinstance)|class\.forname|runtime\.getruntime|runtime\.exec|processbuilder|process\s*\.\s*builder"#).unwrap()
    });
    let _ = RE_SQL_EXTENDED.get_or_init(|| {
        // DBMS-specific functions reachable only through injection: Oracle,
        // MySQL file/network exfil, MSSQL xp_*/openrowset, Postgres file/dblink.
        Regex::new(r#"(?i)\b(?:unistr|updatexml|extractvalue|xmltype|ordsys|ctxsys|dbms_\w+|utl_\w+|load_file|benchmark|xp_cmdshell|xp_reg\w+|xp_dirtree|xp_fileexist|xp_subdirs|openrowset|opendatasource|sp_executesql|sp_oacreate|sp_oamethod|sp_makewebtask|pg_read_file|pg_ls_dir|pg_read_binary_file|pg_stat_file|dblink|dblink_exec|dblink_connect|lo_import|lo_export|generate_series|dbms_pipe|dbms_lock|dbms_aw|dbms_xmlgen|dbms_scheduler|dbms_alert|dbms_output|utl_http|utl_inaddr|utl_file|utl_smtp|utl_tcp|ordsys\.|ctxsys\.|concat_ws|ifnull|nullif|coalesce|greatest|least|locate|instr|to_char|to_date|to_number|to_timestamp|date_format|str_to_date|unix_timestamp|from_unixtime|collate|soundex|difference|lpad|rpad|quote|unhex|octet_length|bit_length|char_length|character_length|initcap|ucase|lcase|substring_index|make_set|export_set|find_in_set|substr|substring|floor|ceil|left|right|ltrim|rtrim|crc32|unhex|oct|conv|elt|field|soundex|difference|make_set|export_set|find_in_set|compress|uncompress)\s*\(|\/\*\+|\binformation_schema\b|\bperformance_schema\b|\bsys\.schema|\barray\s*\[\s*['"]|\blike\s*\(|'\s*union\s+[a-z]+\s*(?:--|#|\/\*|\)|$)|(?:\bor|\band|\bxor)\s*['"]?\s*$|\bor\s*\?\s*--|\bor\s*\(\s*\d+\s*[:=<>!]\s*\d+|\bxor\s+[\w\x0b\x0c]+\s*\d*\s*[<>=!]|\bselect\s*\(\s*case\b|\bcase\s+when\b[^)]*\bthen\b|::(?:int|integer|bigint|smallint|text|varchar|char|numeric|decimal|float|double|real|bool|boolean|date|time|timestamp|interval|json|jsonb|xml|uuid|inet|cidr|macaddr|point|line|lseg|box|path|polygon|circle|money|bit|varbit|tsvector|tsquery|regclass|bytea|name|oid)\b|\blike\s+null\b|\bnot\s+like\s+null\b"#).unwrap()
    });
    let _ = RE_SQL_TAUTOLOGY.get_or_init(|| {
        // Quote-flanked numeric tautologies: ' and 526=527 / " or 1=1.
        // The quote anchor keeps prose like "this and 2=2 that" out.
        Regex::new(r#"(?i)['"][^'"]{0,60}?\b(?:and|or|xor)\s+\d+\s*[:=<>]\s*\d+"#).unwrap()
    });
    let _ = RE_ORM_LOOKUP.get_or_init(|| {
        // Django/SQLAlchemy-style field__lookup chains ending in a known
        // lookup operator — ORM injection that reaches the SQL layer.
        Regex::new(r#"(?i)["']?[a-zA-Z_]\w*(?:__[a-zA-Z_]\w*)*__(?:startswith|istartswith|endswith|iendswith|contains|icontains|iexact|exact|regex|iregex|in|gt|gte|lt|lte|range|isnull|search|unaccent|similar|fulltext|has_key|has_keys|has_any_keys|overlap|contained_by)\b"#).unwrap()
    });
    let _ = RE_RCE_EXTENDED.get_or_init(|| {
        // Windows command constructs and shell-variable indirection that the
        // POSIX chaining rules do not model.
        Regex::new(r#"(?i)\b(?:if\s+(?:not\s+)?exist\b|for\s+%.{1,4}\s+in\b|choice\s+/c|timeout\s+/t|%comspec%|%windir%|%systemroot%|\$\{?IFS\}?|\$SHELL\s+-c|cmd(?:\.exe)?\s+/[ck]\b|forfiles(?:\.exe)?\s+/p|pcalua(?:\.exe)?\s+-a|syncappvpublishingserver|desktopimgdownldr|eventvwr(?:\.exe)?\s+[^\s]*\.msc|presentationhost(?:\.exe)?\s|runscripthelper|msdt(?:\.exe)?\s|pcwrun|xwizard|ie4uinit|infdefaultinstall|gonext|control\.exe\s+[^\s]*\.cpl|invoke-webrequest|invoke-expression|invoke-command|invoke-item|invoke-restmethod|invoke-wmimethod|powershell(?:\.exe)?\s+-\w|pwsh(?:\.exe)?\s+-\w|iex\s*\(|iex\s+-|enter-pssession|new-object|net\.webclient|system\.net\.webclient|downloadstring|downloadfile|get-wmiobject|start-bitstransfer|alias\s+[a-z_]\w*\s*=|!\s*-\d|\btime\s+[a-z_][\w./-]*\s|(?:ba|da|z|k)?sh\s+-c\b|python[0-9.]*\s+-c\b|perl\s+-e\b|ruby\s+-e\b|node\s+-e\b|php\s+-r\b|lua\s+-e\b|tclsh\b|cscli\s|ansible|c89\s|\|\s*(?:vi|vim|nano|emacs|less|more|man|top|htop|mc|ftp|sftp|ssh|telnet|nc|ncat|netcat|socat|awk|gawk|nawk|sed|ed|ex|vi|vim)\b|cmdextversion|\bgoto\s+[a-z_]|\bcall\s+[a-z_%.]|\bstart\s+/|\bif\s+[^\n|]{0,50}==|(?:^|[\s|;&])~[+-]|[|;&]\s*\$[a-zA-Z_]\w*\s+\S|\b(?:dsquery|ntdsutil|dsadd|dsmod|dsrm|netdom|csvde|ldifde|adfind|admod|qwinsta|rwinsta|chgport|dfsvc|ieexec|msbuild|installutil|regasm|regsvcs|sqldmdr|smsdbsrv|cscript|wscript|bcdboot|bcdedit|bootsect|diskpart|schtasks|regsvr32|mshta|wmic|fsutil|takeown|icacls|cacls|compact|cipher|makecab|extrac32|lpq|lpr|rsh|rexec|rlogin)\b|\bif\s+"[^"]{1,30}"\s+(?:geq|leq|gtr|lss|equ|neq)\b|\bset\s+-o\s+\w+|%[@*]\d?|[a-z]\{[a-z][a-z0-9]*,[a-z0-9,]+\}[a-z]|\b(?:nc|ncat|netcat)\s+-[a-zA-Z]*l[a-zA-Z]*\s+\d{2,5}|;\s*set\b)"#).unwrap()
    });
    let _ = RE_METHOD_OVERRIDE_PARAM.get_or_init(|| {
        // _method=PUT/DELETE/PROPFIND style verb tunneling inside the body/qs.
        Regex::new(r#"(?i)(?:^|[?&\s"'])_method\s*=\s*["']?(?:put|delete|patch|post|get|head|options|trace|propfind|proppatch|mkcol|copy|move|lock|unlock|search|acl|bind|unbind|checkout|merge|report|version-control|baseline-control|label|mkworkspace|mkactivity|mkredirectrefworkspace|updateredirectref)\b"#).unwrap()
    });
    let _ = RE_PHP_DANGER.get_or_init(|| {
        // PHP runtime sinks: code-exec, dynamic include, decode helpers and
        // superglobal introspection reachable from request data.
        Regex::new(r#"(?i)(?:^|[^a-z_])(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|dl|create_function|call_user_func(?:_array)?|preg_replace|include|include_once|require|require_once|base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode|hex2bin|get_defined_vars?|get_defined_functions|func_get_args|maybe_unserialize|mb_ereg_replace|show_source|highlight_file|phpinfo|chroot|chdir|chgrp|chown|umask|symlink|link|mkdir|rmdir|unlink|rename|copy|file_put_contents|file_get_contents|fopen|fwrite|fputs|fread|fgets|fclose|readfile|fpassthru|parse_ini_file|token_get_all|get_meta_tags|php_strip_whitespace|stream_wrapper_register|stream_wrapper_unregister|stream_filter_register|spl_autoload_register|spl_autoload_call|assert_options|extract|parse_str|mb_parse_str|import_request_variables|register_tick_function|set_error_handler|set_exception_handler|array_walk|array_walk_recursive|iterator_apply|preg_replace_callback|call_user_method|forward_static_call|mb_ereg_replace|create_function|runkit|uopz|ffi::|FFI::|ReflectionFunction|ReflectionMethod)\s*\(|<\?php|<\?=|`[^`]{1,80}`"#).unwrap()
    });
    let _ = RE_PHP_VAR_SHAPE.get_or_init(|| {
        // PHP variable-function / variable-variable call shapes: $a(...), $$x, ${...}
        Regex::new(r#"(?i)\$\s*\w*\s*\(|\$\$|\$\s*\{|\$\s*\[|->\s*\$\w+|\$\w+\s*->\s*\w+\s*\(|\$\w+\s*\[[^\]]*\]\s*\(|["'][a-zA-Z_]\w*["']\s*\(|(?:^|[^.\w])define\s*\("#).unwrap()
    });
    let _ = RE_NODEJS_ABUSE.get_or_init(|| {
        // Node.js runtime/module surfaces with no place in HTTP parameters.
        Regex::new(r#"(?i)\b(?:require\s*\(|import\s*\(|child_process|process\.(?:env|argv|binding|_linkedbinding|dlopen|exit|kill)|process\s*\[|global\.(?:process|require|buffer|__dirname)|__dirname|__filename|module\.exports|buffer\.from|vm\.runin|vm\.createcontext|worker_threads|cluster\.|fs\.(?:readfile|writefile|createreadstream|createwritestream)|net\.(?:connect|createconnection|createserver)|dgram\.|__proto__|constructor\s*\[|prototype\s*\[|process\[req\.|console\.|__js_function|globalthis|globaleval|this\.constructor|constructor\.constructor|while\s*\(\s*(?:true|!0|1|!!)\s*\)?\s*;|for\s*\(\s*;\s*;|while\s*\(\s*(?:\+?1|true|!0|!!|Infinity|NaN|undefined)\s*\)|atob\s*\(|btoa\s*\(|(?:=|:|=>|return\s+|[(,]\s*)function\s*\([^)]*\)\s*\{|import\s*[{*][^;]{0,300}?\bfrom\b)"#).unwrap()
    });
    // NOTE: data: URIs were removed from RE_NODEJS_ABUSE — they are markup
    // evidence (XSS), not Node runtime abuse, and matched benign data: blobs.
    let _ = RE_JAVA_GADGET.get_or_init(|| {
        // Gadget-class / package vocabulary of RE_JAVA_ATTACK minus the
        // runtime-exec sinks — deserialization evidence only.
        Regex::new(r#"(?i)\b(?:java|javax|sun|com\.sun|oracle|ognl|javassist|xstream|fastjson|mvel|spel|groovy|aspectjweaver|beanshell|jython|mozilla\.rhino|org\.omg|org\.apache\.ibatis|com\.mchange|org\.slf4j|ch\.qos|log4j|org\.apache\.logging|org\.eclipse)\.[a-z]|org\.apache\.commons|com\.opensymphony|org\.springframework|com\.thoughtworks|org\.yaml\.snakeyaml|flex\.messaging|org\.jsecurity|com\.alibaba\.fastjson|xwork\.|struts|webwork|rO0AB|"@type"\s*:\s*"[^"]*(?:java|com\.sun|oracle|ognl|xstream|fastjson|javassist|aspectj|beanshell|jython|rhino|groovy|mvel|spel|opensymphony|springframework)|invokertransformer|templatesimpl|jdbcrowsetimpl|jdk\.internal|clonefactory|ognl\.|spel\.|mvel\.|#\{[a-zA-Z_]|\$\{[a-zA-Z_]+\.(?:get|set|eval|exec|runtime|process|class|forname|newinstance)"#).unwrap()
    });
    let _ = RE_JAVA_SINK.get_or_init(|| {
        // Java runtime exec/loading sinks — command-injection evidence.
        Regex::new(r#"(?i)\b(?:class\s*\.\s*forname|runtime\s*\.\s*getruntime|runtime\s*\.\s*exec|processbuilder|process\s*\.\s*builder)\b"#).unwrap()
    });
    let _ = RE_DATA_URI_MARKUP.get_or_init(|| {
        // data: URIs whose payload is executable markup/script — an XSS
        // vector, not a Node.js runtime signal.
        Regex::new(r#"(?i)\bdata:(?:text/html|text/javascript|application/(?:javascript|x-javascript|ecmascript)|image/svg\+xml)/"#).unwrap()
    });
    let _ = RE_XSS_EXTENDED.get_or_init(|| {
        // JavaScript runtime constructs and executable markup that survive
        // outside <script> tags: new Function, document./window. sinks,
        // dynamic import(), legacy plugin tags.
        Regex::new(r#"(?i)new\s+function\s*\(|document\s*\.\s*(?:cookie|write|writeln|location|domain|referrer|body|forms|images|links|scripts|all|layers|plugins|url|documenturi|baseuri)|window\s*\.\s*(?:location|open|name|top|parent|frames|self|document|opener|event)|window\s*\[|document\s*\[|self\s*\[|top\s*\[|parent\s*\[|frames\s*\[|globalEval|globalThis|setTimeout\s*\(|setInterval\s*\(|queueMicrotask|requestAnimationFrame|eval\s*\(|import\s*\(|confirm\s*\(|prompt\s*\(|alert\s*\(|atob\s*\(|btoa\s*\(|!\[\]|javascript&#\d|\\x[0-9a-f]{2}(?:script|iframe|img|svg|details|video|audio|object|embed|style|link|form|isindex|keygen|marquee|template|noscript|xmp|plaintext|listing)\\x|\b(?:formaction|srcdoc|dynsrc|lowsrc|xlink:href|-moz-binding|expression)\s*[=(]|\bon[a-z]{15,}\s*=|(?:^|[\s"'])[<>!]{0,4}-{2,}>|(?:^|[\s"'(<])!--|<\s*(?:object|applet|isindex|keygen|menuitem|embed|bgsound|ilayer|layer|comment|xml|xss|v:|o:|st1:|w:|rs:)\b|\bon\w{0,30}(?:change|load|play|toggle|focus|blur|error|click|submit|animation|transition|pointer|touch|key|mouse|drag|drop|copy|paste|cut|wheel|scroll|resize|hashchange|popstate|message|open|close|cancel|canplay|ended|pause|seeked|seeking|stalled|suspend|timeupdate|volumechange|waiting|fullscreen|availability|targetavailability)\w{0,20}\s*="#).unwrap()
    });
    let _ = RE_LFI_EXTENDED.get_or_init(|| {
        // Backslash traversal the forward-slash rules do not model. Bare
        // drive-letter/UNC paths are legit client references (file uploads) —
        // only `..\` traversal and its encodings are attack-shaped. The char
        // after the separator must be filename-ish so JSON escapes like `..\"`
        // (Prometheus `5..\"}[5m]`) do not fire.
        Regex::new(r#"(?i)(?:\.\.[\\/][a-zA-Z0-9_.]|%2e%2e%5c|%252e%252e%255c|(?:0x[0-9a-f]{2}){2,}|0x(?:5c|2e|2f|25|00)\b|/\?\?\?/|/(?:etc|proc|sys|var|root|boot|dev|usr|opt|home|tmp)/[^\s"']*[\[\]*]|pa\[s\]d|/etc/passwd|/etc/shadow|/proc/self|/proc/version|/proc/cmdline|\.\.;|\.\.;\\|/sys/|/proc/|\.\.%00|%c0%ae|%e0%80%ae)"#).unwrap()
    });
    let _ = RE_RFI_SCHEME.get_or_init(|| {
        // Non-HTTP URL schemes that only make sense as server-side fetch
        // targets (RFI/SSRF): gopher, dict, file, tftp, ldap, jar, php...
        // ftp/ftps excluded: legit URL-preview params carry them (benign-v5-061).
        Regex::new(r#"(?i)(?:^|[?&\s"'=])(?:gopher|dict|file|tftp|ldap|ldaps|jar|netdoc|expect|php|glob|ogg|zlib|rar|sftp|smb|afp|nfs)://|(?:^|[?&\s"'])(?:file|ftps?|gopher|dict|tftp|ldap|jar|expect|php|glob|ogg|zlib|rar|sftp|smb|nfs|rtmp|rtsp|mms|pnm)\?(?:["'\s]|$)|data:(?:text/(?:html|javascript|json|xml|plain|x-www-form-urlencoded)|application/(?:javascript|json|x-javascript|ecmascript|wasm|x-shockwave-flash)|image/svg)/|\b(?:https?|gopher|dict|ldap|jar|tftp|rtmp|rtsp|ftp)\s*:(?:[^/\s]|/[^/\s]|$)|://\d{8,}\b|\burl:(?:file|https?|ftp|gopher|dict|ldap)|\b(?:https?|ftps?)\?(?:[\s"']|$)"#).unwrap()
    });
    let _ = RE_SESSION_URL.get_or_init(|| {
        // Session identifiers carried in the URL query — fixation/leakage
        // class. Checked against query_string only, never request bodies.
        // query_string arrives without the leading '?', so anchor on ^ too.
        Regex::new(r#"(?i)(?:^|[?&;\s"'])(jsessionid|phpsessid|sessid|sessionid|session_id|aspsessionid|asp\.net_sessionid|phpsessionid|cfid|cftoken|connect\.sid|play_session|phpsession|session_token|rack\.session|_rails_session|rails_session|cakephp|jwsession|cfsid|zend_session_id|symfony_session|laravel_session|django_session|wp-settings|wordpress_logged_in|woocommerce_items_in_cart|jservsession|_session_id|sails\.sid|koa[:.]sess|next-auth\.session|__host-)="#).unwrap()
    });
    let _ = RE_BAD_CHARSET.get_or_init(|| {
        // Exotic/mutable charsets used for parser-differential evasion.
        Regex::new(r#"(?i)(?:charset|_charset_)\s*[=:]\s*["']?(?:utf-?7|utf-?16|utf-?32|unicode|unicodefeff|unicodefffe|x-user-defined|hz-gb-2312|iso-2022-[a-z]+|replacement|x-mac-cyrillic|koi8-[ru]|windows-125[0-9]|ibm[-_]\d+|(?:cp|ibm)(?:37|273|277|278|280|284|285|297|420|424|500|838|870|871|875|1026|1140)\b)"#).unwrap()
    });
    let _ = RE_ABS_URI_METHOD.get_or_init(|| {
        // Request-line smuggling inside a parameter: "GET http://h/ HTTP/1.1".
        Regex::new(r#"(?i)\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|CONNECT|PATCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s+https?://\S+\s+HTTP/\d"#).unwrap()
    });
    let _ = RE_JSON_KEY_SQL.get_or_init(|| {
        // SQL *constructs* inside quoted JSON keys — bare keywords like
        // "where"/"select" are legitimate query-builder keys.
        Regex::new(r#"(?i)["'][^"'\n]{0,50}?(?:union\s+(?:all\s+)?select|select\s+[^"']{1,40}?\s+from|['"]\s*(?:or|and)\s+\w|\bor\s+\d+\s*=\s*\d+|\band\s+\d+\s*=\s*\d+|drop\s+table|insert\s+into|delete\s+from|update\s+\w+\s+set|exec(?:ute)?\s|load_file|into\s+(?:out|dump)file|--|#|/\*|\|\||&&)[^"'\n]{0,50}?["']\s*:"#).unwrap()
    });
    let _ = RE_B64_TOKEN.get_or_init(|| {
        // Standalone base64-ish tokens worth a gadget-substring decode check.
        Regex::new(r#"(?i)["']?([A-Za-z0-9+/]{16,}={0,2})["']?"#).unwrap()
    });
    let _ = RE_SCRIPT_EXT_HDR.get_or_init(|| {
        // Executable/server-side extensions smuggled via filename headers.
        // Trailing dots allowed (IIS/PHP truncation: a.phtml......).
        Regex::new(r#"(?i)\.(?:php[3-8]?p?|phtml?|phar|pht|phps|pl|py|pyc|pyo|rb|cgi|fcgi|jspx?|asp[x]?|ashx|asmx|cer|cdx|htr|shtml?|stm|ssi|action|do|faces|jsf)\.*\s*(?:$|["'\s;&|])"#).unwrap()
    });
    let _ = RE_HEX_PAIRS.get_or_init(|| {
        // Adjacent 0xHH hex-byte runs — encoded traversal/null shapes.
        Regex::new(r#"(?i)(?:0x[0-9a-f]{2}){2,}"#).unwrap()
    });
    let _ = RE_IPV6_LITERAL.get_or_init(|| {
        // IPv6 literals in URLs: http://[::1]/, scheme:[::ffff:...], etc.
        Regex::new(r#"(?i)\[([0-9a-fA-F:]{2,}(?::[0-9a-fA-F]{0,4})+)%?[0-9a-zA-Z]*\]"#).unwrap()
    });
    let _ = RE_OCTAL_IP.get_or_init(|| {
        // Dotted quads with octal-looking parts: 0251.0376.0251.0376.
        Regex::new(r#"(?i)\b0\d{2,3}(?:\.0?\d{1,3}){3}\b"#).unwrap()
    });
    let _ = RE_PHP_INI_KEY.get_or_init(|| {
        // PHP ini-style dotted keys reaching ini_set/config: opcache.jit_*,
        // disable_functions.*, session.*, upload_tmp_dir.* etc.
        Regex::new(r#"(?i)(?:opcache|apc|xcache|wincache|eaccelerator|hhvm|newrelic|datadog|blackfire|xdebug|uopz|suhosin|runkit|zend|ffi|phar|session|upload_tmp_dir|sys_temp_dir|include_path|open_basedir|disable_functions|allow_url_fopen|allow_url_include|auto_prepend_file|auto_append_file|error_log|display_errors|expose_php|mail|intl|mbstring|pdo|mysqli|mysqlnd|pgsql|sqlite|soap|curl|openssl|zlib|bcmath|gmp|date|exif|filter|iconv|json|ldap|libxml|fastcgi|realpath_cache)\.[a-z_]"#).unwrap()
    });
    let _ = RE_MULTIPART_BAD_FN.get_or_init(|| {
        // Multipart filename carrying = ; | & % — parser-differential names.
        Regex::new(r#"(?i)filename\s*=\s*["'][^"']*[=;|&%][^"']*["']"#).unwrap()
    });
    let _ = RE_NESTED_PARAM.get_or_init(|| {
        // Param value shaped like another assignment: month=( / CType='
        Regex::new(r#"(?i)(?:^|[\s&"'])[a-z_][\w.-]{1,30}=[('\[{]"#).unwrap()
    });
    let _ = RE_ENTITY_NAME.get_or_init(|| {
        // Bare HTML-entity fragments (amp; lt; gt; quot; apos;) inside quoted
        // multipart/form field names — desync bait between parsers.
        Regex::new(
            r#"(?i)(?:name|filename)\s*=\s*"[^"]*(?:amp|lt|gt|quot|apos|nbsp|copy|reg);[^"]*""#,
        )
        .unwrap()
    });
    let _ = RE_SQL_ERROR_MSG.get_or_init(|| {
        // Database error strings reflected inside request bodies — inbound
        // probes that elicit or replay engine diagnostics.
        Regex::new(r#"(?i)\b(?:sql syntax|mysql_fetch|mysqli?_query|mssql_query|pg_query|ora-\d{3,5}|sqlstate|dynamic sql error|invalid input syntax for|supplied argument is not|xpath syntax error|frontbase|odbc_|sql server|jdbc\s+(?:driver|sql)|unterminated string|unclosed quotation|you have an error in your sql|maxdb::|incorrect syntax near|database error|db2 sql error|sqlite3?::|warning:\s+\w+::query|near \"[a-z]+\":)\b"#).unwrap()
    });
    let _ = RE_CRLF_HEADER.get_or_init(|| {
        // Decoded CRLF reconstructing an HTTP header line.
        Regex::new(r#"(?i)[\r\n]+\s*[a-z][a-z0-9-]{1,30}\s*:"#).unwrap()
    });
    let _ = RE_CRLF_PARAM.get_or_init(|| {
        // Decoded LF/CRLF splitting a value into what looks like k=v pairs.
        Regex::new(r#"(?i)[\r\n]+\s*[a-zA-Z_][\w.-]{0,30}\s*="#).unwrap()
    });
    let _ = RE_TEMPLATE_DIR.get_or_init(|| {
        // FreeMarker/Velocity/Thymeleaf directive syntax in param values.
        Regex::new(r#"(?i)#(?:foreach|list|if|elseif|else|set|assign|macro|function|include|parse|evaluate|define|literal|compress|escape|noescape|nested|sep|switch|case|default|recurse|visit|attempt|recover|import|global|local|stop|break|continue|return|t|rt|lt|noparse)\s*[({$]|\$[a-z]\w{0,20}\.(?:invoke|eval|exec|runtime|getruntime|processbuilder)\s*\("#).unwrap()
    });
    let _ = RE_PHP_INI_ASSIGN.get_or_init(|| {
        // php.ini-style key=value assignments smuggled in params (no dotted
        // prefix needed — precision=, arg_separator.output=, etc.).
        Regex::new(r#"(?i)(?:^|[?&\s"'{};,])(?:precision|serialize_precision|arg_separator\.input|arg_separator\.output|variables_order|request_order|auto_prepend_file|auto_append_file|docref_root|user_dir|upload_tmp_dir|sys_temp_dir|include_path|open_basedir|disable_classes|disable_functions|allow_url_fopen|allow_url_include|display_errors|error_log|expose_php|max_execution_time|max_input_time|memory_limit|post_max_size|upload_max_filesize|file_uploads|short_open_tag|asp_tags|zend\.assertions|opcache\.[a-z_]+|apc\.[a-z_]+|xcache\.[a-z_]+|wincache\.[a-z_]+|eaccelerator\.[a-z_]+|hhvm\.[a-z_]+|newrelic\.[a-z_]+|xdebug\.[a-z_]+|uopz\.[a-z_]+|suhosin\.[a-z_]+|runkit\.[a-z_]+|ffi\.[a-z_]+|phar\.[a-z_]+|session\.[a-z_]+|intl\.[a-z_]+|mbstring\.[a-z_]+|pdo\.[a-z_]+|mysqli?\.[a-z_]+|pgsql\.[a-z_]+|sqlite3?\.[a-z_]+|soap\.[a-z_]+|curl\.[a-z_]+|openssl\.[a-z_]+|zlib\.[a-z_]+|bcmath\.[a-z_]+|gmp\.[a-z_]+|exif\.[a-z_]+|filter\.[a-z_]+|iconv\.[a-z_]+|ldap\.[a-z_]+|libxml\.[a-z_]+|fastcgi\.[a-z_]+|realpath_cache\.[a-z_]+)\s*="#).unwrap()
    });
    let _ = RE_SENSITIVE_FILE.get_or_init(|| {
        // High-value local files reachable through traversal/LFI probes.
        Regex::new(r#"(?i)(?:subuid|subgid|backup\.[\w.-]+\.(?:zip|tar|gz|tgz|sql|bak|7z|rar)|\.docker/secrets|\.git-credentials|\.aws/credentials|\.ssh/id_|\.kube/config|\.npmrc|\.pypirc|\.dockercfg|\.pgpass|\.my\.cnf|\.netrc|\.htpasswd|\.htaccess|\.git/config|\.svn/entries|\.hg/store|\.bzr/|\.idea/|\.vscode/|composer\.(?:json|lock)|package-lock\.json|yarn\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|go\.sum|Cargo\.lock|\.env\.(?:local|prod|dev|production|staging)?|\.env$|\.env\b|web\.config|appsettings\.(?:json|Development\.json)|settings\.py|database\.yml|database\.yaml|secrets?\.(?:json|ya?ml|toml|env)|credentials?\.(?:json|xml|ini|cfg|conf)|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem$|\.key$|\.p12$|\.pfx$|\.keystore$|\.jks$|\.kdbx$)"#).unwrap()
    });
    let _ = RE_ERROR_REFLECT.get_or_init(|| {
        // Framework/runtime exception names and stack frames reflected in
        // request bodies (outbound-error replay / error-oracle probes).
        Regex::new(r#"(?i)\b(?:Http\w*(?:Exception|Error)|HttpSessionState\w*|HttpParse\w*|HttpCompile\w*|HttpStaticObjects\w*|System\.[\w.]*Exception|\w+Exception\s*:|at\s+[\w.$]+\([\w.$]+:\d+\)|\{\s*"status"\s*:\s*5\d\d\s*\}|\bstatus["']?\s*[:=]\s*5\d\d\b|Internal Server Error|Stack Trace|NullPointerException|ClassCastException|SQLException|PersistenceException|TransactionSystemException)"#).unwrap()
    });
    let _ = RE_CRED_QUERY.get_or_init(|| {
        // Credentials transported in the URL query string — session/credential
        // material must never appear in URLs (logs, referers, history).
        Regex::new(r#"(?i)(?:^|[?&;\s"'])(?:password|passwd|user_password|user_pass|login_password|pwd|pass)\s*="#).unwrap()
    });
    let _ = RE_IPV6_URL.get_or_init(|| {
        // Bracketed IPv6 literal behind a scheme — param-value regexes stop
        // at ']' so this must run on the whole normalized text.
        Regex::new(r#"(?i)://\[([0-9a-fA-F:]{2,}(?::[0-9a-fA-F]{0,4})*)\]"#).unwrap()
    });
    let _ = RE_LOCALHOST_DNS.get_or_init(|| {
        // Public DNS names / TLDs that resolve to loopback or private space.
        Regex::new(r#"(?i)(?:\b(?:lvh|vcap|localtest|lacolhost)\.me\b|\b(?:nip|sslip|xip)\.io\b|\bmetadata\.packet\.net\b|\bmetadata\.google\.internal\b|\binstance-data\b|\.(?:localhost|local|internal|lan|corp|home|intranet|svc|consul)\b)"#).unwrap()
    });
    let _ = RE_PARAM_PAIR_WIDE.get_or_init(|| {
        // Like RE_PARAM_PAIR but the value may contain whitespace/CRLF —
        // needed to see protocol commands smuggled inside a parameter.
        Regex::new(r#"(?i)["']?([a-z_][a-z0-9_.\-]{0,40})["']?\s*[:=]\s*["']?([^&"',}\]]{1,300})"#)
            .unwrap()
    });
    let _ = RE_APPLIANCE_CVE.get_or_init(|| {
        // Known-vulnerable appliance/admin endpoints (PAN-OS, FortiGate,
        // Cisco ASA/AnyConnect, Pulse, Ivanti, Citrix, F5, Exchange, Atlassian).
        Regex::new(r#"(?i)/(?:remote/login|remote/logincheck|dana-na/|\+CSCOE\+|global-protect/|cgi-bin/login\.cgi|owa/|ecp/|autodiscover/|mifs/|console/|por/login|webconsole/|saml/metadata|plugins/servlet/gadgets|secure/QueryComponent|rest/api/2/user\?|rest/api/2/dashboard|rest/tinymce|_/download/resources/com\.atlassian|jira/secure|confluence/display|solr/admin/info/system|geoserver/web|actuator/gateway|nacos/v1|druid/|xxl-job-admin|apisix/admin|apisix/dashboard|grafana/api|kibana/app|portainer/|rancher/|proxmox/|unifi/|truenas/|freenas/|openmediavault/|cockpit/|webmin/|user/login|manager/html|host-manager/html|jmx-console/|web-console/|invoker/JMXInvokerServlet|jbpm-console|admin-console/|status\?full=true|server-info|server-status)"#).unwrap()
    });
}

impl AstLexer {
    /// Multi-pass recursive URL decode, comment stripper, and Unicode homoglyph normalizer.
    pub fn normalize_string(raw: &str) -> (String, bool) {
        init_regexes();
        let mut is_obfuscated = false;
        if raw.contains('%')
            || raw.contains("/**/")
            || raw.contains("\\u")
            || raw.contains("\\x")
            || raw.contains("&#")
            || raw.contains("/*!")
        {
            is_obfuscated = true;
        }

        // JSON unicode escapes (\u0026 etc.) decode before entity layers so
        // $\u0026lbrace; reaches the JSP-EL entity decode as $&lbrace;.
        let raw_uesc = Self::decode_json_unicode_escapes(raw);
        if raw_uesc != raw {
            is_obfuscated = true;
        }

        // JSP EL brace entities collapse to template delimiters (both cases —
        // JSON-unescaped payloads arrive lowercase).
        let raw_lbrace = if raw_uesc.contains("$&LBRACE;")
            || raw_uesc.contains("$&RBRACE;")
            || raw_uesc.contains("$&lbrace;")
            || raw_uesc.contains("$&rbrace;")
        {
            is_obfuscated = true;
            raw_uesc
                .replace("$&LBRACE;", "${")
                .replace("$&RBRACE;", "}")
                .replace("$&lbrace;", "${")
                .replace("$&rbrace;", "}")
        } else {
            raw_uesc
        };

        // Pass 0: Overlong UTF-8 / IIS encodings decode to replacement chars if left to the
        // UTF-8 decoder, so rewrite them into `.`, `/`, `\` before percent decoding.
        let raw_path = Self::decode_overlong_encodings(&raw_lbrace);
        if raw_path != raw {
            is_obfuscated = true;
        }

        // Pass 1: Decode
        let d1 = percent_decode_str(&raw_path)
            .decode_utf8_lossy()
            .to_string();
        // Pass 2: Nested decode
        let d2 = percent_decode_str(&d1).decode_utf8_lossy().to_string();
        // Pass 3: MySQL executable comments run on the server; unwrap them, then strip plain comments.
        let d2_exec = Self::extract_mysql_exec_comments(&d2);
        if d2_exec != d2 {
            is_obfuscated = true;
        }
        let re_comment = RE_COMMENT_STRIP.get().unwrap();
        let d3 = re_comment.replace_all(&d2_exec, " ").to_string();

        // Pass 3.5: HTML entities and control characters used to split schemes.
        let (d3_html, entity_changed) = Self::decode_html_entities(&d3);
        if entity_changed {
            is_obfuscated = true;
        }
        let d3_ctrl = Self::collapse_intra_word_controls(&d3_html);

        // Pass 4: Unicode Homoglyphs & Fullwidth ASCII normalization (U+FF01-U+FF5E -> U+0021-U+007E)
        let mut d4 = String::with_capacity(d3_ctrl.len());
        for c in d3_ctrl.chars() {
            match c {
                '\u{FF01}'..='\u{FF5E}' => {
                    is_obfuscated = true;
                    d4.push(char::from_u32((c as u32) - 0xFEE0).unwrap_or(c));
                }
                '\u{3000}' => {
                    is_obfuscated = true;
                    d4.push(' ');
                }
                '\u{2215}' | '\u{2044}' | '\u{29F8}' => {
                    is_obfuscated = true;
                    d4.push('/');
                }
                '\u{2216}' => {
                    is_obfuscated = true;
                    d4.push('\\');
                }
                '\u{2024}' => {
                    is_obfuscated = true;
                    d4.push('.');
                }
                '\u{3002}' | '\u{FF61}' => {
                    // Ideographic full stop / halfwidth ideographic full stop
                    is_obfuscated = true;
                    d4.push('.');
                }
                '\u{2028}' | '\u{2029}' => {
                    // Line/paragraph separator — normalize to LF so CRLF checks see it
                    is_obfuscated = true;
                    d4.push('\n');
                }
                '\u{24EA}' | '\u{24FF}' => {
                    // Circled / negative-circled digit zero
                    is_obfuscated = true;
                    d4.push('0');
                }
                '\u{2460}'..='\u{2473}' => {
                    // Circled digits ①-⑳ -> 1-20 (multi-digit values emit both chars)
                    is_obfuscated = true;
                    let n = c as u32 - 0x245F;
                    if n <= 9 {
                        d4.push(char::from_digit(n, 10).unwrap_or(c));
                    } else {
                        d4.push_str(&n.to_string());
                    }
                }
                '\u{2474}'..='\u{2487}' => {
                    // Parenthesized digits ⑴-⒇ -> 1-20
                    is_obfuscated = true;
                    let n = c as u32 - 0x2473;
                    if n <= 9 {
                        d4.push(char::from_digit(n, 10).unwrap_or(c));
                    } else {
                        d4.push_str(&n.to_string());
                    }
                }
                '\u{24F5}'..='\u{24FE}' => {
                    // Circled small digits ⓵-⓾ -> 1-9,0
                    is_obfuscated = true;
                    let n = c as u32 - 0x24F4;
                    if n <= 9 {
                        d4.push(char::from_digit(n, 10).unwrap_or(c));
                    } else {
                        d4.push('0');
                    }
                }
                '\u{2776}'..='\u{277F}' => {
                    // Negative circled digits ❶-❿ -> 1-10
                    is_obfuscated = true;
                    let n = c as u32 - 0x2775;
                    if n <= 9 {
                        d4.push(char::from_digit(n, 10).unwrap_or(c));
                    } else {
                        d4.push_str("10");
                    }
                }
                '\0' => {
                    is_obfuscated = true;
                    // Null byte: map to '/' so ..%00/etc becomes ..//etc traversal
                    d4.push('/');
                }
                // Cyrillic/Greek homoglyph fold: attackers spell keywords with
                // lookalike letters (ѕеlесt, раураӏ). Fold to ASCII so the
                // existing detectors see the canonical keyword.
                'а' | 'А' => {
                    is_obfuscated = true;
                    d4.push('a');
                }
                'с' | 'С' => {
                    is_obfuscated = true;
                    d4.push('c');
                }
                'е' | 'Е' | 'ё' | 'Ё' => {
                    is_obfuscated = true;
                    d4.push('e');
                }
                'о' | 'О' => {
                    is_obfuscated = true;
                    d4.push('o');
                }
                'р' | 'Р' => {
                    is_obfuscated = true;
                    d4.push('p');
                }
                'х' | 'Х' => {
                    is_obfuscated = true;
                    d4.push('x');
                }
                'у' | 'У' => {
                    is_obfuscated = true;
                    d4.push('y');
                }
                'і' | 'І' => {
                    is_obfuscated = true;
                    d4.push('i');
                }
                'ј' | 'Ј' => {
                    is_obfuscated = true;
                    d4.push('j');
                }
                'ѕ' | 'Ѕ' => {
                    is_obfuscated = true;
                    d4.push('s');
                }
                'һ' | 'Һ' => {
                    is_obfuscated = true;
                    d4.push('h');
                }
                'ԁ' | 'ԃ' => {
                    is_obfuscated = true;
                    d4.push('d');
                }
                'ԛ' | 'Ԛ' => {
                    is_obfuscated = true;
                    d4.push('q');
                }
                'ԝ' | 'Ԝ' => {
                    is_obfuscated = true;
                    d4.push('w');
                }
                'в' | 'В' => {
                    is_obfuscated = true;
                    d4.push('b');
                }
                'к' | 'К' => {
                    is_obfuscated = true;
                    d4.push('k');
                }
                'м' | 'М' => {
                    is_obfuscated = true;
                    d4.push('m');
                }
                'н' | 'Н' => {
                    is_obfuscated = true;
                    d4.push('h');
                }
                'т' | 'Т' => {
                    is_obfuscated = true;
                    d4.push('t');
                }
                'ӏ' => {
                    is_obfuscated = true;
                    d4.push('l');
                }
                'ſ' => {
                    is_obfuscated = true;
                    d4.push('s');
                }
                'K' => {
                    is_obfuscated = true;
                    d4.push('k');
                }
                // Invisible/bidi controls: strip so `un<U+200B>ion` collapses
                // to `union` and bidi-reordered `java<U+202E>script` loses its
                // smuggling power. Emoji ZWJ is collateral — acceptable, the
                // original bytes still reach upstream untouched.
                '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{E0000}'..='\u{E007F}' => {
                    is_obfuscated = true;
                }
                // Combining marks (accents stacked on base letters)
                '\u{0300}'..='\u{036F}' => {
                    is_obfuscated = true;
                }
                _ => d4.push(c),
            }
        }

        // Pass 5: Decode JSON/Unicode/Hex escapes (\uXXXX and \xXX) in any case, including dots, quotes, slashes, brackets
        let mut d5 = d4.clone();
        if d5.contains("\\u")
            || d5.contains("\\U")
            || d5.contains("\\x")
            || d5.contains("\\X")
            || d5.contains("\\r")
            || d5.contains("\\n")
            || d5.contains("\\t")
            || d5.contains("\\b")
            || d5.contains("\\f")
            || d5.contains("\\/")
            || d5.contains("\\\"")
            || d5.contains("\\\\")
        {
            let mut decoded = String::with_capacity(d5.len());
            let chars: Vec<char> = d5.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                // JSON simple escapes: \r \n \t \b \f \/ \" \\ — decoded so
                // CRLF smuggled inside JSON string values becomes visible.
                if i + 1 < chars.len() && chars[i] == '\\' {
                    let esc = match chars[i + 1] {
                        'r' => Some('\r'),
                        'n' => Some('\n'),
                        't' => Some('\t'),
                        'b' => Some('\u{8}'),
                        'f' => Some('\u{c}'),
                        '/' => Some('/'),
                        '"' => Some('"'),
                        '\\' => Some('\\'),
                        _ => None,
                    };
                    if let Some(ch) = esc {
                        decoded.push(ch);
                        i += 2;
                        continue;
                    }
                }
                if i + 5 < chars.len()
                    && chars[i] == '\\'
                    && (chars[i + 1] == 'u' || chars[i + 1] == 'U')
                {
                    let hex_str: String = chars[i + 2..=i + 5].iter().collect();
                    if let Ok(code) = u32::from_str_radix(&hex_str, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            decoded.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                } else if i + 3 < chars.len()
                    && chars[i] == '\\'
                    && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
                {
                    let hex_str: String = chars[i + 2..=i + 3].iter().collect();
                    if let Ok(code) = u32::from_str_radix(&hex_str, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            decoded.push(ch);
                            i += 4;
                            continue;
                        }
                    }
                }
                decoded.push(chars[i]);
                i += 1;
            }
            d5 = decoded;
        }

        // Pass 6: Log4j nested lookup syntax `${lower:j}ndi` / `${upper:L}DAP`.
        let d6 = Self::expand_jndi_obfuscation(&d5);
        if d6 != d5 {
            is_obfuscated = true;
        }

        // Pass 7: `+` is a space in query strings but a literal elsewhere; keep a
        // decoded variant so `net+user` and `;+cat` resolve like their spaced form.
        let d7 = if raw_path.contains('+') {
            raw_path.replace('+', " ")
        } else {
            raw_path.clone()
        };
        // Combined variant: percent-decoded AND plus-as-space. Without it,
        // `Uncompress+%28` keeps `+` literal in d1/d2 and keeps `%28` encoded
        // in d7 — the payload slips between the two interpretations.
        let d7b = if d3.contains('+') {
            d3.replace('+', " ")
        } else {
            d3.clone()
        };

        // Pass 8: Long 0x-hex literals may carry ASCII-encoded SQL (`0x556e696f6e...`).
        let (d8, hex_changed) = Self::decode_hex_blobs(&raw_path);
        if hex_changed {
            is_obfuscated = true;
        }

        // Only keep distinct variants: identical copies multiply regex scan time and can
        // create matches that do not exist in any single interpretation of the payload.
        let mut parts: Vec<&str> = vec![raw];
        for variant in [
            raw_path.as_str(),
            d1.as_str(),
            d2.as_str(),
            d3.as_str(),
            d3_html.as_str(),
            d3_ctrl.as_str(),
            d4.as_str(),
            d5.as_str(),
            d6.as_str(),
            d7.as_str(),
            d7b.as_str(),
            d8.as_str(),
        ] {
            if !parts.contains(&variant) {
                parts.push(variant);
            }
        }
        (parts.join(" "), is_obfuscated)
    }

    /// Replaces printable `0x<hex>{16,}` blobs with their ASCII decode so encoded
    /// SQL text (`0x556e696f6e...` -> "Union ...") becomes visible to the lexer.
    fn decode_hex_blobs(text: &str) -> (String, bool) {
        if !text.contains("0x") && !text.contains("0X") {
            return (text.to_string(), false);
        }
        let re = RE_HEX_BLOB.get().unwrap();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let mut changed = false;
        for m in re.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            let hex = &m.as_str()[2..];
            let decoded: Vec<u8> = (0..hex.len() / 2)
                .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            let printable = !decoded.is_empty()
                && decoded
                    .iter()
                    .filter(|b| b.is_ascii_graphic() || **b == b' ')
                    .count()
                    * 10
                    >= decoded.len() * 8;
            if printable {
                out.push(' ');
                out.push_str(&String::from_utf8_lossy(&decoded));
                out.push(' ');
                changed = true;
            } else {
                out.push_str(m.as_str());
            }
            last = m.end();
        }
        out.push_str(&text[last..]);
        (out, changed)
    }

    fn decode_overlong_encodings(raw: &str) -> String {
        if !raw.contains('%') {
            return raw.to_string();
        }
        let mut decoded = RE_OVERLONG_DOT
            .get()
            .unwrap()
            .replace_all(raw, ".")
            .to_string();
        decoded = RE_OVERLONG_SLASH
            .get()
            .unwrap()
            .replace_all(&decoded, "/")
            .to_string();
        decoded = RE_OVERLONG_BACKSLASH
            .get()
            .unwrap()
            .replace_all(&decoded, "\\")
            .to_string();
        decoded = RE_IIS_DOT
            .get()
            .unwrap()
            .replace_all(&decoded, ".")
            .to_string();
        decoded = RE_IIS_SLASH
            .get()
            .unwrap()
            .replace_all(&decoded, "/")
            .to_string();
        decoded = RE_IIS_BACKSLASH
            .get()
            .unwrap()
            .replace_all(&decoded, "\\")
            .to_string();
        decoded = RE_IIS_LT
            .get()
            .unwrap()
            .replace_all(&decoded, "<")
            .to_string();
        decoded = RE_IIS_GT
            .get()
            .unwrap()
            .replace_all(&decoded, ">")
            .to_string();
        decoded = RE_IIS_SQUOTE
            .get()
            .unwrap()
            .replace_all(&decoded, "'")
            .to_string();
        decoded = RE_IIS_DQUOTE
            .get()
            .unwrap()
            .replace_all(&decoded, "\"")
            .to_string();
        decoded = RE_IIS_GUILLEMET_L
            .get()
            .unwrap()
            .replace_all(&decoded, "<")
            .to_string();
        RE_IIS_GUILLEMET_R
            .get()
            .unwrap()
            .replace_all(&decoded, ">")
            .to_string()
    }

    /// Decode JSON-style `\uXXXX` escapes (incl. surrogate pairs) found in
    /// string bodies. Leaves non-escape text untouched.
    fn decode_json_unicode_escapes(raw: &str) -> String {
        if !raw.contains("\\u") {
            return raw.to_string();
        }
        let bytes = raw.as_bytes();
        let mut out = String::with_capacity(raw.len());
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'\\'
                && i + 5 < bytes.len()
                && bytes[i + 1] == b'u'
                && bytes[i + 2..i + 6].iter().all(|b| b.is_ascii_hexdigit())
            {
                let hex = std::str::from_utf8(&bytes[i + 2..i + 6]).unwrap_or("");
                if let Ok(cp) = u32::from_str_radix(hex, 16) {
                    // Handle UTF-16 surrogate pairs.
                    if (0xD800..0xDC00).contains(&cp)
                        && i + 11 < bytes.len()
                        && bytes[i + 6] == b'\\'
                        && bytes[i + 7] == b'u'
                    {
                        let hex2 = std::str::from_utf8(&bytes[i + 8..i + 12]).unwrap_or("");
                        if let Ok(lo) = u32::from_str_radix(hex2, 16) {
                            if (0xDC00..0xE000).contains(&lo) {
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                if let Some(ch) = char::from_u32(c) {
                                    out.push(ch);
                                    i += 12;
                                    continue;
                                }
                            }
                        }
                    }
                    if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                        i += 6;
                        continue;
                    }
                }
            }
            // Copy one full UTF-8 char.
            let ch = raw[i..].chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    fn extract_mysql_exec_comments(text: &str) -> String {
        if !text.contains("/*!") {
            return text.to_string();
        }
        RE_MYSQL_EXEC_COMMENT
            .get()
            .unwrap()
            .replace_all(text, " $1 ")
            .to_string()
    }

    fn decode_html_entities(text: &str) -> (String, bool) {
        if !text.contains('&') {
            return (text.to_string(), false);
        }
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut changed = false;
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '&' {
                let mut j = i + 1;
                while j < chars.len()
                    && j - i <= 12
                    && chars[j] != ';'
                    && (chars[j].is_ascii_alphanumeric() || chars[j] == '#')
                {
                    j += 1;
                }
                if j < chars.len() && chars[j] == ';' && j > i + 1 {
                    let body: String = chars[i + 1..j].iter().collect();
                    let decoded = if let Some(hex) =
                        body.strip_prefix("#x").or_else(|| body.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                    } else if let Some(dec) = body.strip_prefix('#') {
                        dec.parse::<u32>().ok().and_then(char::from_u32)
                    } else {
                        Self::named_html_entity(&body)
                    };
                    if let Some(ch) = decoded {
                        out.push(ch);
                        changed = true;
                        i = j + 1;
                        continue;
                    }
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        (out, changed)
    }

    fn named_html_entity(name: &str) -> Option<char> {
        match name.to_ascii_lowercase().as_str() {
            "colon" => Some(':'),
            "tab" => Some('\t'),
            "newline" => Some('\n'),
            "lpar" => Some('('),
            "rpar" => Some(')'),
            "sol" => Some('/'),
            "bsol" => Some('\\'),
            "period" => Some('.'),
            "comma" => Some(','),
            "semi" => Some(';'),
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            "num" => Some('#'),
            _ => None,
        }
    }

    fn collapse_intra_word_controls(text: &str) -> String {
        if !text
            .bytes()
            .any(|b| b == b'\t' || b == b'\n' || b == b'\r' || b == 0)
        {
            return text.to_string();
        }
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let is_control = c == '\t' || c == '\n' || c == '\r' || c == '\0';
            if is_control
                && i > 0
                && i + 1 < chars.len()
                && chars[i - 1].is_ascii_alphanumeric()
                && chars[i + 1].is_ascii_alphabetic()
            {
                i += 1;
                continue;
            }
            out.push(c);
            i += 1;
        }
        out
    }

    fn expand_jndi_obfuscation(text: &str) -> String {
        let lower = text.to_ascii_lowercase();
        if !lower.contains("${lower:")
            && !lower.contains("${upper:")
            && !lower.contains("${env:")
            && !lower.contains("${date:")
            && !lower.contains("${::-")
        {
            return text.to_string();
        }
        let casing = RE_JNDI_OBFUSCATION.get().unwrap();
        let env = RE_JNDI_ENV_LOOKUP.get().unwrap();
        let char_extract = RE_JNDI_CHAR_EXTRACT.get().unwrap();
        let date = RE_JNDI_DATE_LOOKUP.get().unwrap();
        let mut current = text.to_string();
        for _ in 0..4 {
            let next = char_extract.replace_all(&current, "$1").to_string();
            let next = date.replace_all(&next, "$1").to_string();
            let next = casing
                .replace_all(&next, |caps: &regex::Captures| {
                    let mode = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    if mode.eq_ignore_ascii_case("lower") {
                        body.to_ascii_lowercase()
                    } else {
                        body.to_ascii_uppercase()
                    }
                })
                .to_string();
            let next = env.replace_all(&next, "$1").to_string();
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn has_ssrf_param_context(text: &str) -> bool {
        let private = RE_SSRF_PRIVATE.get().unwrap();
        let context = RE_SSRF_PARAM_CONTEXT.get().unwrap();
        for matched in private.find_iter(text) {
            let start = matched.start();
            let mut window_start = start.saturating_sub(64);
            while window_start > 0 && !text.is_char_boundary(window_start) {
                window_start -= 1;
            }
            if context.is_match(&text[window_start..start]) {
                return true;
            }
        }
        false
    }

    fn has_internal_host_context(text: &str) -> bool {
        let internal = RE_SSRF_INTERNAL_TLD.get().unwrap();
        let context = RE_SSRF_PARAM_CONTEXT.get().unwrap();
        for matched in internal.find_iter(text) {
            let start = matched.start();
            let mut window_start = start.saturating_sub(64);
            while window_start > 0 && !text.is_char_boundary(window_start) {
                window_start -= 1;
            }
            if context.is_match(&text[window_start..start]) {
                return true;
            }
        }
        false
    }

    /// Host / forwarding-header integrity check. An IP literal in `Host`, or a
    /// forwarding header (`X-Forwarded-Host`, `X-Host`, `Forwarded`) that
    /// disagrees with it, is how password-reset and cache-poisoning attacks
    /// smuggle attacker-controlled hostnames.
    fn analyze_host_headers(headers: &HashMap<String, String>) -> bool {
        let mut host_value = "";
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") {
                host_value = v.trim();
                break;
            }
        }
        let host_is_ip = Self::is_ip_literal(host_value) || Self::is_internal_hostname(host_value);
        if host_is_ip {
            return true;
        }
        for (k, v) in headers {
            let kl = k.to_ascii_lowercase();
            let val = v.trim();
            if val.is_empty() {
                continue;
            }
            match kl.as_str() {
                "x-forwarded-host"
                | "x-host"
                | "x-original-host"
                | "x-forwarded-server"
                | "x-http-host-forwarded"
                | "front-end-https"
                | "x-http-host-override"
                | "x-rewrite-host"
                | "x-http-host"
                | "x-server-name" => {
                    // A forwarding header alone is normal proxy traffic; it is
                    // hostile when it is an IP literal, disagrees with Host, or
                    // arrives with no Host at all on a spoof-prone header name.
                    let spoof_prone = matches!(
                        kl.as_str(),
                        "x-forwarded-host"
                            | "x-host"
                            | "x-original-host"
                            | "x-forwarded-server"
                            | "x-http-host-override"
                            | "x-rewrite-host"
                            | "x-http-host"
                            | "x-server-name"
                    );
                    if Self::is_ip_literal(val)
                        || Self::is_internal_hostname(val)
                        || (!host_value.is_empty() && !val.eq_ignore_ascii_case(host_value))
                        || (host_value.is_empty() && spoof_prone)
                    {
                        return true;
                    }
                }
                "x-original-url" | "x-rewrite-url" | "x-override-url" | "x-original-uri" => {
                    // URL-rewrite headers can silently reroute the request;
                    // hostile when absolute or pointing at privileged paths.
                    let lv = val.to_ascii_lowercase();
                    if lv.contains("://")
                        || lv.contains("/admin")
                        || lv.contains("wp-admin")
                        || lv.contains("phpmyadmin")
                        || lv.contains("/actuator")
                        || lv.contains("/.git")
                        || lv.contains("/server-status")
                    {
                        return true;
                    }
                }
                "forwarded" => {
                    // RFC 7239: Forwarded: for=...;host=example.com;proto=https
                    for part in val.split(';') {
                        if let Some((name, value)) = part.split_once('=') {
                            if name.trim().eq_ignore_ascii_case("host") {
                                let fwd_host = value.trim().trim_matches('"');
                                if Self::is_ip_literal(fwd_host)
                                    || (!host_value.is_empty()
                                        && !fwd_host.eq_ignore_ascii_case(host_value))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn is_ip_literal(value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        let v = value.trim().trim_start_matches('[').trim_end_matches(']');
        // Dotted-quad IPv4 (optionally with :port or decimal/hex single forms).
        // Short forms like 127.1 and 127.0.1 are also IP literals.
        let quad = v.split(':').next().unwrap_or(v);
        if quad.contains('.') {
            let parts: Vec<&str> = quad.split('.').collect();
            return parts.len() >= 2
                && parts.len() <= 4
                && parts.iter().all(|p| {
                    !p.is_empty()
                        && p.len() <= 4
                        && p.bytes().all(|b| b.is_ascii_digit())
                        && (p.len() <= 3 || p.starts_with('0'))
                });
        }
        // Bare integer / hex IP or IPv6 literal
        if v.bytes().all(|b| b.is_ascii_digit()) && !v.is_empty() {
            return true;
        }
        if v.starts_with("0x") || v.contains(':') {
            return true;
        }
        false
    }

    /// Classify an IPv6 literal (without brackets) as loopback/private/
    /// link-local/reserved — the ranges an edge SSRF filter must reject.
    fn is_internal_ipv6(inner: &str) -> bool {
        let s = inner.split('%').next().unwrap_or(inner); // strip zone id
        if s == "::1" || s == "::" {
            return true;
        }
        let lower = s.to_ascii_lowercase();
        // ::ffff:a.b.c.d IPv4-mapped — recurse on the dotted tail.
        if let Some(tail) = lower.strip_prefix("::ffff:") {
            if tail.contains('.') {
                return Self::is_internal_ipv4_str(tail);
            }
            // hex form ::ffff:a9fe:a9fe — last 32 bits as two hextets.
            let parts: Vec<&str> = tail.split(':').collect();
            if parts.len() == 2 {
                if let (Ok(hi), Ok(lo)) = (
                    u16::from_str_radix(parts[0], 16),
                    u16::from_str_radix(parts[1], 16),
                ) {
                    let ip = format!(
                        "{}.{}.{}.{}",
                        (hi >> 8) as u8,
                        (hi & 0xff) as u8,
                        (lo >> 8) as u8,
                        (lo & 0xff) as u8
                    );
                    return Self::is_internal_ipv4_str(&ip);
                }
            }
            return false;
        }
        // fe80::/10 link-local, fc00::/7 ULA, fec0::/10 site-local, ff00::/8 multicast.
        lower.starts_with("fe8")
            || lower.starts_with("fe9")
            || lower.starts_with("fea")
            || lower.starts_with("feb")
            || lower.starts_with("fc")
            || lower.starts_with("fd")
            || lower.starts_with("fec")
            || lower.starts_with("ff")
    }

    /// IPv4 private/loopback/link-local/reserved check for mapped forms.
    fn is_internal_ipv4_str(ip: &str) -> bool {
        let it = ip.split('.');
        let octets: Vec<u8> = it.filter_map(|p| p.parse::<u8>().ok()).collect();
        if octets.len() != 4 {
            return false;
        }
        let [a, b, c, _] = [octets[0], octets[1], octets[2], octets[3]];
        a == 0 || a == 10 || a == 127 || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
            || (a == 100 && (64..=127).contains(&b)) || (a == 198 && (b == 18 || b == 19))
            || (a == 192 && b == 0 && c == 2)   // TEST-NET-1 (documentation, non-routable)
            || (a == 198 && b == 51 && c == 100) // TEST-NET-2
            || (a == 203 && b == 0 && c == 113)  // TEST-NET-3
            || a >= 224 // multicast + reserved + broadcast
    }

    /// Internal-only hostnames that should never appear in a public Host header
    /// or forwarding header at the edge.
    fn is_internal_hostname(value: &str) -> bool {
        let v = value.trim().trim_start_matches('[').trim_end_matches(']');
        let host = v.split(':').next().unwrap_or(v).to_ascii_lowercase();
        host == "localhost"
            || host.ends_with(".localhost")
            || host.ends_with(".local")
            || host.ends_with(".internal")
            || host.ends_with(".lan")
            || host.ends_with(".corp")
            || host.ends_with(".home")
            || host.ends_with(".intranet")
            || host.ends_with(".svc")
            || host.ends_with(".consul")
            || host == "metadata"
            || host == "instance-data"
            || host == "kubernetes"
            || host == "docker"
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
                        tokens
                            .active_token_names
                            .push("TAUTOLOGY_EQUALS".to_string());
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
                        tokens
                            .active_token_names
                            .push("TAUTOLOGY_EQUALS".to_string());
                        break;
                    }
                }
            }
        }
        if !tokens.has_tautology {
            if let Some(numeric) = RE_TAUT_NUMERIC.get() {
                for cap in numeric.captures_iter(&normalized) {
                    let left = cap.get(1).and_then(|m| m.as_str().parse::<i64>().ok());
                    let right = cap.get(3).and_then(|m| m.as_str().parse::<i64>().ok());
                    let op = cap.get(2).map(|m| m.as_str()).unwrap_or("");
                    let always_true = match (left, right, op) {
                        (Some(a), Some(b), ">") => a > b,
                        (Some(a), Some(b), "<") => a < b,
                        (Some(a), Some(b), ">=") => a >= b,
                        (Some(a), Some(b), "<=") => a <= b,
                        (Some(a), Some(b), "!=") => a != b,
                        _ => false,
                    };
                    if always_true {
                        tokens.has_tautology = true;
                        tokens
                            .active_token_names
                            .push("TAUTOLOGY_NUMERIC".to_string());
                        break;
                    }
                }
            }
        }
        if !tokens.has_tautology && RE_OR_NUMERIC_COMMENT.get().unwrap().is_match(&normalized) {
            tokens.has_tautology = true;
            tokens
                .active_token_names
                .push("TAUTOLOGY_NUMERIC_COMMENT".to_string());
        }
        if RE_UNION_SELECT.get().unwrap().is_match(&normalized) {
            // Bare "union select" is also a legitimate search phrase; require
            // projection/table context (quote, FROM, NULL, comment, wildcard).
            let union_ctx = normalized.contains('\'')
                || normalized.contains('"')
                || norm_lower.contains(" from ")
                || norm_lower.contains("null")
                || norm_lower.contains("--")
                || norm_lower.contains("/*")
                || normalized.contains("*");
            if union_ctx {
                tokens.has_union_select = true;
                tokens.active_token_names.push("UNION_CLAUSE".to_string());
                tokens
                    .active_token_names
                    .push("SELECT_PROJECTION".to_string());
            }
        }
        if RE_SQL_SLEEP.get().unwrap().is_match(&normalized) {
            tokens.has_time_delay = true;
            tokens
                .active_token_names
                .push("TIME_DELAY_FUNCTION".to_string());
        }
        if RE_STACKED_DDL.get().unwrap().is_match(&normalized) {
            tokens.has_stacked_ddl = true;
            tokens.active_token_names.push("STACKED_DDL".to_string());
        }

        // 2. XSS Tokens. Gate: every XSS pattern needs markup or a URI scheme.
        let has_markup_or_uri = normalized.contains('<')
            || normalized.contains("javascript:")
            || normalized.contains("vbscript:")
            || normalized.contains("data:");
        if has_markup_or_uri && RE_XSS_SCRIPT.get().unwrap().is_match(&normalized) {
            tokens.has_script_tag = true;
            tokens.active_token_names.push("SCRIPT_ELEMENT".to_string());
        }
        if has_markup_or_uri && RE_XSS_REMOTE_SCRIPT.get().unwrap().is_match(&normalized) {
            tokens.has_script_tag = true;
            tokens
                .active_token_names
                .push("REMOTE_SCRIPT_INCLUDE".to_string());
        }
        if has_markup_or_uri && RE_XSS_EVENT.get().unwrap().is_match(&normalized) {
            tokens.has_event_handler = true;
            tokens
                .active_token_names
                .push("INLINE_EVENT_HANDLER".to_string());
        }
        if has_markup_or_uri && RE_XSS_SVG.get().unwrap().is_match(&normalized) {
            tokens.has_svg_onload = true;
            tokens.active_token_names.push("SVG_ONLOAD".to_string());
        }
        if has_markup_or_uri && RE_XSS_JS_URI.get().unwrap().is_match(&normalized) {
            tokens.has_js_scheme = true;
            tokens.active_token_names.push("JS_URI_SCHEME".to_string());
        }

        // 3. Command Injection / RCE Tokens. Gate: shell metacharacters, or the
        // interpreter names that can appear bare in a parameter value.
        let has_shell_byte = normalized
            .bytes()
            .any(|b| matches!(b, b';' | b'|' | b'&' | b'`' | b'$' | b'\n' | b'\r' | b'('));
        let has_interpreter_name = norm_lower.contains("powershell")
            || norm_lower.contains("base64")
            || norm_lower.contains("cmd")
            || norm_lower.contains("certutil")
            || norm_lower.contains("mshta")
            || norm_lower.contains("rundll32")
            || norm_lower.contains("regsvr32")
            || norm_lower.contains("wmic")
            || norm_lower.contains("bitsadmin");
        if has_shell_byte || has_interpreter_name {
            if RE_SHELL_CHAIN.get().unwrap().is_match(&normalized) {
                tokens.has_shell_chain = true;
                tokens.active_token_names.push("SHELL_METACHAR".to_string());
                tokens
                    .active_token_names
                    .push("SYSTEM_BINARY_INVOCATION".to_string());
            }
            if RE_SUBSHELL.get().unwrap().is_match(&normalized) {
                let has_bin = [
                    "cat", "curl", "wget", "id", "whoami", "uname", "ls", "bash", "sh",
                ]
                .iter()
                .any(|&bin| norm_lower.contains(bin));
                if has_bin {
                    tokens.has_subshell = true;
                    tokens
                        .active_token_names
                        .push("SUBSHELL_EXPANSION".to_string());
                }
            }
            if RE_DYNAMIC_EVAL.get().unwrap().is_match(&normalized)
                || RE_POWERSHELL_EXEC.get().unwrap().is_match(&normalized)
            {
                tokens.has_dynamic_eval = true;
                tokens
                    .active_token_names
                    .push("DYNAMIC_CODE_RUNTIME".to_string());
            }
            if RE_BASE64_DECODE.get().unwrap().is_match(&normalized) {
                tokens.has_shell_chain = true;
                tokens
                    .active_token_names
                    .push("BASE64_DECODE_EXECUTION".to_string());
            }
        }

        // 4. Path Traversal Tokens. Gate: traversal always involves dots,
        // percent-encoding, or a known filesystem root.
        let has_traversal_hint = normalized.contains("..")
            || normalized.contains("%2")
            || normalized.contains("etc")
            || normalized.contains("proc")
            || normalized.contains("winnt")
            || normalized.contains("system32")
            || normalized.contains("win.ini")
            || norm_lower.contains("kubernetes")
            || normalized.contains("secrets/")
            || norm_lower.contains("windows")
            || normalized.contains("boot")
            || normalized.contains("/dev/")
            || normalized.contains("\\\\")
            || normalized.contains("=//");
        if has_traversal_hint
            && (RE_PATH_TRAVERSAL.get().unwrap().is_match(&normalized)
                || (RE_PATH_DOTS_ONLY.get().unwrap().is_match(&normalized)
                    && (raw_text.contains('/')
                        || raw_text.contains('\\')
                        || raw_text.contains('%'))))
        {
            tokens.has_path_traversal = true;
            tokens
                .active_token_names
                .push("DIR_TRAVERSAL_DOT_DOT".to_string());
        }
        // Tomcat-style `..;/` and `..%3B/` path-parameter traversal variants.
        if normalized.contains("..;/")
            || normalized.contains("..%3b")
            || normalized.contains("..%3B")
        {
            tokens.has_path_traversal = true;
            tokens
                .active_token_names
                .push("DIR_TRAVERSAL_PATH_PARAM".to_string());
        }
        // UNC paths (\\host\share) and scheme-relative file targets (//host.tld/path)
        // in file-ish positions. normalize_string() joins the raw payload with
        // every decoded variant, so JSON-escaped \\ survives verbatim; a UNC
        // match that ends in a common document/media extension is a legitimate
        // file reference (\\server\share\report.xlsx), not a payload drop.
        if normalized.contains("\\\\") || normalized.contains("=//") {
            let unc_hit = RE_UNC_PATH
                .get()
                .unwrap()
                .find_iter(&normalized)
                .any(|m| !RE_UNC_BENIGN_EXT.get().unwrap().is_match(m.as_str()));
            if unc_hit {
                tokens.has_path_traversal = true;
                tokens
                    .active_token_names
                    .push("UNC_PATH_TARGET".to_string());
            }
        }
        // NTFS alternate data streams: file.txt:streamname
        if RE_ADS_PATH.get().unwrap().is_match(&normalized)
            && (has_traversal_hint
                || norm_lower.contains("file")
                || norm_lower.contains("upload")
                || norm_lower.contains("attach")
                || norm_lower.contains("doc")
                || norm_lower.contains("name=")
                || norm_lower.contains("path=")
                || norm_lower.contains("f="))
        {
            tokens.has_path_traversal = true;
            tokens
                .active_token_names
                .push("NTFS_ADS_STREAM".to_string());
        }
        if has_traversal_hint && RE_PATH_DIRECT_SYSTEM.get().unwrap().is_match(&normalized) {
            tokens.has_sensitive_system_path = true;
            tokens
                .active_token_names
                .push("DIRECT_SYSTEM_FILE_TARGET".to_string());
        }

        // 5. SSRF Tokens. Cloud metadata is always a violation. Loopback/RFC1918
        // targets are only violations when they appear in a URL-like parameter,
        // otherwise documentation and issue text trigger false positives.
        // Gate: every SSRF signature is an IP literal, localhost, or metadata host.
        let has_ssrf_hint = normalized.contains("://")
            || normalized.contains("127.")
            || normalized.contains("10.")
            || normalized.contains("192.168")
            || normalized.contains("169.254")
            || normalized.contains("0.0.0.0")
            || norm_lower.contains("localhost")
            || norm_lower.contains("metadata");
        if !has_ssrf_hint {
            // skip both SSRF checks
        } else if RE_SSRF_CLOUD.get().unwrap().is_match(&normalized) {
            tokens.has_ssrf_metadata = true;
            tokens
                .active_token_names
                .push("CLOUD_METADATA_ENDPOINT".to_string());
        } else if RE_SSRF_PRIVATE.get().unwrap().is_match(&normalized)
            && Self::has_ssrf_param_context(&normalized)
        {
            tokens.has_ssrf_metadata = true;
            tokens
                .active_token_names
                .push("PRIVATE_NETWORK_ENDPOINT".to_string());
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
        if gql.has_abuse {
            tokens.has_graphql_abuse = true;
            tokens.active_token_names.extend(gql.active_tokens.clone());
        }

        // 7. JSON Strict & Prototype Pollution (decoded text catches \u-escaped keys)
        let js = JsonStrictAnalyzer::analyze(&normalized);
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
        // admin-ajax.php is legitimate functional traffic (heartbeat, plugin
        // actions), not a reconnaissance probe; keep it out of the shield.
        if RE_WORDPRESS_PROBE.get().unwrap().is_match(&normalized)
            && !norm_lower.contains("admin-ajax.php")
        {
            tokens.has_wordpress_probe = true;
            tokens
                .active_token_names
                .push("WORDPRESS_RECON_PROBE".to_string());
        }
        // xmlrpc.php is only a probe when it carries an actual XML-RPC method
        // call; bare GETs (?rsd discovery) are legitimate.
        if !tokens.has_wordpress_probe
            && normalized.contains("xmlrpc.php")
            && (normalized.contains("methodCall")
                || norm_lower.contains("wp.get")
                || norm_lower.contains("system.listMethods")
                || norm_lower.contains("pingback.ping"))
        {
            tokens.has_wordpress_probe = true;
            tokens
                .active_token_names
                .push("WORDPRESS_RECON_PROBE".to_string());
        }
        if RE_SENSITIVE_EXPOSURE.get().unwrap().is_match(&normalized) {
            tokens.has_sensitive_file_probe = true;
            tokens
                .active_token_names
                .push("SENSITIVE_FILE_EXPOSURE_PROBE".to_string());
        }
        if RE_FRAMEWORK_EXPLOIT.get().unwrap().is_match(&normalized) {
            tokens.has_framework_exploit_probe = true;
            tokens
                .active_token_names
                .push("FRAMEWORK_EXPLOIT_PAYLOAD".to_string());
        }

        // 10. NoSQL Injection Tokens: Mongo-style operator keys in JSON or bracket form.
        // Gate: a `$` byte is mandatory for every operator form.
        if normalized.contains('$')
            && (RE_NOSQL_JSON_OP.get().unwrap().is_match(&normalized)
                || RE_NOSQL_BRACKET_OP.get().unwrap().is_match(&normalized))
        {
            tokens.has_nosql_operator = true;
            tokens
                .active_token_names
                .push("NOSQL_OPERATOR_INJECTION".to_string());
        }
        // MongoDB diagnostic/admin commands (no $ prefix), CouchDB/Elasticsearch
        // data endpoints, and SQL statements inside JSON fields.
        if RE_NOSQL_ADMIN_CMD.get().unwrap().is_match(&normalized)
            || RE_NOSQL_DB_PATH.get().unwrap().is_match(&normalized)
        {
            tokens.has_nosql_operator = true;
            tokens
                .active_token_names
                .push("NOSQL_ADMIN_COMMAND".to_string());
        }
        if normalized.contains('{') && RE_SQL_JSON_FIELD.get().unwrap().is_match(&normalized) {
            tokens.has_sqli_subquery = true;
            tokens
                .active_token_names
                .push("SQLI_JSON_FIELD".to_string());
        }

        // 11. Server-Side Template Injection Tokens: engine delimiters coupled with sinks.
        // Gate: every template family needs a delimiter byte.
        if (normalized.contains("{{")
            || normalized.contains("${")
            || normalized.contains("#set")
            || normalized.contains("#if")
            || normalized.contains("#foreach")
            || normalized.contains("#evaluate")
            || normalized.contains("#include")
            || normalized.contains("#parse")
            || normalized.contains("#define")
            || normalized.contains("#macro")
            || normalized.contains("#elseif")
            || normalized.contains("#assign")
            || normalized.contains("<#"))
            && (RE_SSTI_JINJA.get().unwrap().is_match(&normalized)
                || RE_SSTI_FREEMARKER.get().unwrap().is_match(&normalized)
                || RE_SSTI_VELOCITY.get().unwrap().is_match(&normalized))
        {
            tokens.has_ssti_expression = true;
            tokens
                .active_token_names
                .push("SSTI_TEMPLATE_EXPRESSION".to_string());
        }

        // 12. HTTP Response Splitting: decoded CRLF introducing a response header.
        // Multipart bodies legitimately carry Content-Type/Content-Disposition
        // after CRLF, so generic header matching excludes those there.
        let is_multipart =
            norm_lower.contains("content-disposition") && norm_lower.contains("form-data");
        let mut crlf_hit = (normalized.contains('\r') || normalized.contains('\n'))
            && RE_CRLF_RESPONSE_HDR.get().unwrap().is_match(&normalized);
        if !crlf_hit && normalized.contains("\r\n") {
            // Strict CRLF + any header-shaped token, gated on mail/upload-ish
            // context to avoid flagging YAML/JSON line breaks.
            let mailish = norm_lower.contains("mime")
                || norm_lower.contains("boundary")
                || norm_lower.contains("filename")
                || norm_lower.contains("attachment")
                || norm_lower.contains("subject")
                || norm_lower.contains("content-type")
                || norm_lower.contains("content-disposition")
                || norm_lower.contains('@');
            for m in RE_CRLF_ANY_HDR.get().unwrap().find_iter(&normalized) {
                // Parameter-assignment context: an '=' in the 64 chars before
                // the CRLF indicates a query/body value, not a YAML/JSON break.
                let wstart = m.start().saturating_sub(64);
                let window = &normalized[wstart..m.start()];
                let param_eq = window
                    .rfind('=')
                    .map(|i| {
                        let tail = &window[i..];
                        !tail.contains('\n') && !tail.contains('\r') && !tail.contains('{')
                    })
                    .unwrap_or(false);
                if !mailish && !param_eq {
                    continue;
                }
                // Extract the header name after \r\n[ \t]*
                let tail = &normalized[m.start()..];
                let name_end = tail
                    .trim_start_matches("\r\n")
                    .trim_start_matches(|c: char| c == ' ' || c == '\t')
                    .find(':')
                    .unwrap_or(0);
                let name = tail
                    .trim_start_matches("\r\n")
                    .trim_start_matches(|c: char| c == ' ' || c == '\t')
                    .get(..name_end)
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if is_multipart
                    && (name == "content-type"
                        || name == "content-disposition"
                        || name == "content-location"
                        || name == "content-range"
                        || name == "content-md5")
                {
                    continue;
                }
                // MIME part-header sequence: filename="x"\r\nContent-Type: ...
                // is how multipart bodies are serialized even when the request
                // headers don't declare multipart/form-data (raw MIME posts).
                if (name == "content-type" || name == "content-disposition")
                    && normalized[..m.start()]
                        .rfind("filename=")
                        .map(|i| m.start() - i < 200)
                        .unwrap_or(false)
                {
                    continue;
                }
                crlf_hit = true;
                break;
            }
        }
        if !crlf_hit && !is_multipart && (normalized.contains('\r') || normalized.contains('\n')) {
            // Same MIME part-header exemption as the ANY_HDR loop: a
            // filename="x"\r\nContent-Type: sequence is a serialized body
            // part, not response splitting.
            crlf_hit = RE_CRLF_CONTENT_HDR
                .get()
                .unwrap()
                .find_iter(&normalized)
                .any(|m| {
                    normalized[..m.start()]
                        .rfind("filename=")
                        .map(|i| m.start() - i >= 200)
                        .unwrap_or(true)
                });
        }
        if RE_EMAIL_ENCODED_WORD.get().unwrap().is_match(&normalized) {
            crlf_hit = true;
        }
        // RFC 2047 Q-encoded CRLF inside an encoded-word: =?UTF-8?Q?...=0D=0A...
        // decodes to a raw header break server-side regardless of charset.
        if norm_lower.contains("=?")
            && (norm_lower.contains("=0d=0a") || norm_lower.contains("=0a=0d"))
        {
            crlf_hit = true;
        }
        if crlf_hit {
            tokens.has_crlf_header_injection = true;
            tokens
                .active_token_names
                .push("CRLF_RESPONSE_HEADER_INJECTION".to_string());
        }

        // 13. Malicious Upload: executable filename, or server-side tag in upload context.
        // Gate: filename params and server-side tags are the only entry points.
        if (norm_lower.contains("filename")
            || norm_lower.contains("file_name")
            || norm_lower.contains("filepath")
            || norm_lower.contains("upload")
            || normalized.contains("<?")
            || normalized.contains("<%"))
            && (RE_UPLOAD_FILENAME.get().unwrap().is_match(&normalized)
                || (RE_SERVER_SIDE_TAG.get().unwrap().is_match(&normalized)
                    && RE_UPLOAD_CTX.get().unwrap().is_match(&normalized)))
        {
            tokens.has_malicious_upload = true;
            tokens
                .active_token_names
                .push("MALICIOUS_UPLOAD_PAYLOAD".to_string());
        }

        // 14. Expanded SSRF Targets: alternate loopback encodings, rebinding domains,
        // and internal-only TLDs (the last only inside URL-shaped parameters).
        // jrt:/ uses a single slash, so the gate also accepts it.
        // Gate: every SSRF pattern is scheme-prefixed.
        if normalized.contains("://") || normalized.contains("jrt:/") {
            if RE_SSRF_ALT_TARGET.get().unwrap().is_match(&normalized) {
                tokens.has_ssrf_metadata = true;
                tokens
                    .active_token_names
                    .push("ALTERNATE_NETWORK_TARGET".to_string());
            }
            if RE_SSRF_INTERNAL_TLD.get().unwrap().is_match(&normalized)
                && Self::has_internal_host_context(&normalized)
            {
                tokens.has_ssrf_metadata = true;
                tokens
                    .active_token_names
                    .push("INTERNAL_TLD_ENDPOINT".to_string());
            }
            // Cloud/exfil-capable schemes (s3://, gs://, ssh2://, ldap://, ...) behind
            // a URL-shaped parameter.
            for m in RE_SSRF_CLOUD_SCHEME.get().unwrap().find_iter(&normalized) {
                let start = m.start();
                let mut ws = start.saturating_sub(64);
                while ws > 0 && !normalized.is_char_boundary(ws) {
                    ws -= 1;
                }
                if RE_SSRF_PARAM_CONTEXT
                    .get()
                    .unwrap()
                    .is_match(&normalized[ws..start])
                {
                    tokens.has_ssrf_metadata = true;
                    tokens
                        .active_token_names
                        .push("CLOUD_SCHEME_ENDPOINT".to_string());
                    break;
                }
            }
        }

        // 15. Windows-native shell binaries behind a metacharacter gate.
        if RE_WIN_SHELL_BINARY.get().unwrap().is_match(&normalized)
            && RE_SHELL_METACHAR_GATE.get().unwrap().is_match(&normalized)
        {
            tokens.has_shell_chain = true;
            tokens
                .active_token_names
                .push("WINDOWS_SYSTEM_BINARY".to_string());
            tokens.active_token_names.push("SHELL_METACHAR".to_string());
        }

        // 15b. Config/exec tricks needing no metacharacter: sed -e 'e', tar
        // --checkpoint-action, find -exec, git core.pager, BEGIN{system},
        // openssl s_client, telnet host port, whois/nslookup/ping $var.
        if RE_CMD_EXEC_TRICK.get().unwrap().is_match(&normalized) {
            tokens.has_shell_chain = true;
            tokens.active_token_names.push("CMD_EXEC_TRICK".to_string());
        }

        // 16. Error-based / blind / file-write SQL primitives need an injection
        // context (quote, comment, UNION or SELECT) to avoid flagging prose.
        // Gate: every listed function is invoked with `(`.
        if RE_SQL_ERROR_FUNC.get().unwrap().is_match(&normalized)
            && (normalized.contains('(')
                || norm_lower.contains("into outfile")
                || norm_lower.contains("into dumpfile")
                || norm_lower.contains("waitfor delay"))
            && (tokens.has_quote
                || tokens.has_union_select
                || tokens.has_stacked_ddl
                || normalized.contains("--")
                || norm_lower.contains("select"))
        {
            tokens.has_sqli_danger_func = true;
            tokens
                .active_token_names
                .push("SQLI_DANGER_FUNCTION".to_string());
        }

        // 17. PHP stream wrappers abused for command exec or arbitrary file read.
        // Gate: wrappers are always scheme-prefixed.
        if normalized.contains("://") && RE_PHP_WRAPPER.get().unwrap().is_match(&normalized) {
            tokens.has_path_traversal = true;
            tokens
                .active_token_names
                .push("PHP_STREAM_WRAPPER".to_string());
        }

        // 18. Shellshock function export: () { :;}; <command>
        // Gate: the signature requires braces.
        if normalized.contains('{') && RE_SHELLSHOCK.get().unwrap().is_match(&normalized) {
            tokens.has_shell_chain = true;
            tokens
                .active_token_names
                .push("SHELLSHOCK_FUNCTION_EXPORT".to_string());
        }

        // 19. Absolute-path binaries and busybox applets behind a metacharacter.
        // Gate: both alternatives require `/` or the literal `busybox`.
        if (normalized.contains('/') || norm_lower.contains("busybox"))
            && RE_PATH_BINARY.get().unwrap().is_match(&normalized)
            && RE_SHELL_METACHAR_GATE.get().unwrap().is_match(&normalized)
        {
            tokens.has_shell_chain = true;
            tokens
                .active_token_names
                .push("ABSOLUTE_PATH_BINARY".to_string());
            tokens.active_token_names.push("SHELL_METACHAR".to_string());
        }

        // 20. XXE external / parameter entities reaching SYSTEM or PUBLIC ids,
        // plus external refs that resolve attacker resources without a DOCTYPE
        // (xml-stylesheet href, xml:base, xi:include href).
        if normalized.contains("<!") && RE_XXE_ENTITY.get().unwrap().is_match(&normalized) {
            tokens.has_xxe_entity = true;
            tokens
                .active_token_names
                .push("XXE_EXTERNAL_ENTITY".to_string());
        }
        if normalized.contains('<') && RE_XXE_REF.get().unwrap().is_match(&normalized) {
            tokens.has_xxe_entity = true;
            tokens
                .active_token_names
                .push("XXE_EXTERNAL_REFERENCE".to_string());
        }

        // 21. Quote-free SQLi: subqueries, CASE WHEN and HAVING tautologies.
        if norm_lower.contains("select") && RE_SQL_SUBQUERY.get().unwrap().is_match(&normalized) {
            tokens.has_sqli_subquery = true;
            tokens.active_token_names.push("SQLI_SUBQUERY".to_string());
        }
        if (norm_lower.contains("case") || norm_lower.contains("having"))
            && RE_SQL_CASE_HAVING.get().unwrap().is_match(&normalized)
        {
            tokens.has_sqli_case_having = true;
            tokens
                .active_token_names
                .push("SQLI_CASE_HAVING".to_string());
        }
        // UNION/SELECT with /* */ comments inside the keywords themselves.
        if normalized.contains("/**/") && RE_UNION_SELECT_OBF.get().unwrap().is_match(&normalized) {
            tokens.has_union_select = true;
            tokens
                .active_token_names
                .push("UNION_SELECT_OBFUSCATED".to_string());
        }

        // 22. Command binary glued to ${IFS} whitespace substitution.
        if norm_lower.contains("ifs") && RE_CMD_IFS_BINARY.get().unwrap().is_match(&normalized) {
            tokens.has_cmd_ifs_binary = true;
            tokens.has_shell_chain = true;
            tokens.active_token_names.push("CMD_IFS_BINARY".to_string());
            tokens.active_token_names.push("SHELL_METACHAR".to_string());
            tokens
                .active_token_names
                .push("SYSTEM_BINARY_INVOCATION".to_string());
        }

        // 23. SSTI arithmetic probes and embedded template tags.
        if (normalized.contains("{{")
            || normalized.contains("${")
            || normalized.contains("<%")
            || normalized.contains("#{")
            || normalized.contains("*{")
            || norm_lower.contains("expr")
            || norm_lower.contains("template")
            || norm_lower.contains("eval"))
            && (RE_SSTI_ARITH.get().unwrap().is_match(&normalized)
                || RE_SSTI_EXPR_PARAM.get().unwrap().is_match(&normalized))
        {
            tokens.has_ssti_arith = true;
            tokens
                .active_token_names
                .push("SSTI_ARITHMETIC_PROBE".to_string());
        }
        if normalized.contains("<%") && RE_SSTI_EMBEDDED.get().unwrap().is_match(&normalized) {
            tokens.has_ssti_embedded = true;
            tokens
                .active_token_names
                .push("SSTI_EMBEDDED_TAG".to_string());
        }
        // Smarty single-brace tags: {eval}, {php}, {insert}, {fetch}, {include}
        if normalized.contains('{') && RE_SSTI_SMARTY.get().unwrap().is_match(&normalized) {
            tokens.has_ssti_expression = true;
            tokens
                .active_token_names
                .push("SSTI_SMARTY_TAG".to_string());
        }

        // 24. SSRF via userinfo trick and scheme-relative URLs.
        if normalized.contains("://")
            && normalized.contains('@')
            && RE_SSRF_USERINFO.get().unwrap().is_match(&normalized)
        {
            tokens.has_ssrf_userinfo = true;
            tokens.has_ssrf_metadata = true;
            tokens
                .active_token_names
                .push("SSRF_USERINFO_TRICK".to_string());
        }
        if normalized.contains("//") {
            for m in RE_SSRF_SCHEME_REL.get().unwrap().find_iter(&normalized) {
                let start = m.start();
                let mut ws = start.saturating_sub(64);
                while ws > 0 && !normalized.is_char_boundary(ws) {
                    ws -= 1;
                }
                if RE_SSRF_PARAM_CONTEXT
                    .get()
                    .unwrap()
                    .is_match(&normalized[ws..start])
                {
                    tokens.has_ssrf_scheme_rel = true;
                    tokens.has_ssrf_metadata = true;
                    tokens
                        .active_token_names
                        .push("SSRF_SCHEME_RELATIVE".to_string());
                    break;
                }
            }
        }

        // 25. LDAP filter injection: metacharacters plus directory attribute context.
        if (normalized.contains(")(")
            || normalized.contains("(|")
            || normalized.contains("*)")
            || normalized.contains("=*")
            || normalized.contains("(&"))
            && RE_LDAP_META.get().unwrap().is_match(&normalized)
            && (norm_lower.contains("uid")
                || norm_lower.contains("cn=")
                || norm_lower.contains("objectclass")
                || norm_lower.contains("userpassword")
                || norm_lower.contains("samaccountname")
                || norm_lower.contains("distinguishedname")
                || norm_lower.contains("memberof")
                || norm_lower.contains("dn=")
                || norm_lower.contains("ou=")
                || norm_lower.contains("mail=")
                || norm_lower.contains("sn=")
                || norm_lower.contains("givenname")
                || norm_lower.contains("displayname")
                || norm_lower.contains("user")
                || norm_lower.contains("login")
                || norm_lower.contains("pass")
                || norm_lower.contains("filter")
                || norm_lower.contains("search")
                || norm_lower.contains("directory")
                || norm_lower.contains("telephonenumber"))
        {
            tokens.has_ldap_injection = true;
            tokens
                .active_token_names
                .push("LDAP_FILTER_INJECTION".to_string());
        }
        // Hex-escaped LDAP wildcard: \2a decodes to '*' server-side. Legitimate
        // filters write '*' literally, so the escape itself is the signal.
        if norm_lower.contains("\\2a")
            && (norm_lower.contains("\"u\"")
                || norm_lower.contains("u=")
                || norm_lower.contains("uid")
                || norm_lower.contains("user")
                || norm_lower.contains("login")
                || norm_lower.contains("cn=")
                || norm_lower.contains("dn=")
                || norm_lower.contains("mail")
                || norm_lower.contains("telephonenumber")
                || norm_lower.contains("auth"))
        {
            tokens.has_ldap_injection = true;
            tokens
                .active_token_names
                .push("LDAP_HEX_WILDCARD_ESCAPE".to_string());
        }

        // 26. Insecure deserialization object markers (Java/PHP/.NET/Python/Node).
        if (norm_lower.contains("ro0ab")
            || norm_lower.contains("/wep")
            || norm_lower.contains("aaeaaad")
            || norm_lower.contains("a:")
            || norm_lower.contains("o:")
            || norm_lower.contains("aced")
            || norm_lower.contains("h4si")
            || norm_lower.contains("_$$nd_func")
            || norm_lower.contains("__php_incomplete")
            || norm_lower.contains("c:")
            || norm_lower.contains("s:")
            || normalized.contains('\n'))
            && RE_DESERIALIZATION.get().unwrap().is_match(&normalized)
        {
            tokens.has_deserialization = true;
            tokens
                .active_token_names
                .push("INSECURE_DESERIALIZATION".to_string());
        }

        // 27. PHP higher-order callables + variable-function invocation.
        if normalized.contains('(')
            && (RE_PHP_FUNC_CALLBACK.get().unwrap().is_match(&normalized)
                || RE_PHP_DOLLAR_BRACE_CALL
                    .get()
                    .unwrap()
                    .is_match(&normalized)
                || RE_PHP_EVAL_MODIFIER.get().unwrap().is_match(&normalized)
                || RE_PHP_GADGET_CLASS.get().unwrap().is_match(&normalized)
                || (normalized.contains("$")
                    && (RE_PHP_CONCAT_ASSIGN.get().unwrap().is_match(&normalized)
                        || RE_PHP_VAR_CALL.get().unwrap().is_match(&normalized))))
        {
            tokens.has_dynamic_eval = true;
            tokens
                .active_token_names
                .push("PHP_CALLABLE_INJECTION".to_string());
        }

        // 28. Windows living-off-the-land binaries (hostile without metachars).
        if RE_WIN_LOLBIN.get().unwrap().is_match(&normalized) {
            tokens.has_shell_chain = true;
            tokens.active_token_names.push("WINDOWS_LOLBIN".to_string());
        }

        // 29. XPath location-path / function / axis injection.
        // Path regex fires on structural probes; function names need a //, ::,
        // or quote context; axes (::) are self-contained. Matches whose // is
        // part of a scheme:// URL are skipped (char before // must not be ':').
        let xpath_path_hit = RE_XPATH_EXPR
            .get()
            .unwrap()
            .find_iter(&normalized)
            .any(|m| {
                let before = m.start().saturating_sub(1);
                let prev = normalized.as_bytes().get(before);
                // Skip scheme:// URLs and ../-style traversal: `//etc/passwd`
                // inside `....//....//etc/passwd` is a path escape, not XPath.
                prev != Some(&b':') && prev != Some(&b'.')
            });
        if xpath_path_hit
            || RE_XPATH_AXIS.get().unwrap().is_match(&normalized)
            || norm_lower.contains("generate-id(")
            || norm_lower.contains("processing-instruction(")
            || (RE_XPATH_FUNC
                .get()
                .unwrap()
                .find_iter(&normalized)
                .any(|m| {
                    // Skip JS method calls: el.text(), obj.key(), node.id()
                    m.start() == 0 || normalized.as_bytes()[m.start() - 1] != b'.'
                })
                && (normalized.contains("//")
                    || normalized.contains("::")
                    || normalized.contains('\'')
                    || normalized.contains('"')))
        {
            tokens.has_xpath_injection = true;
            tokens
                .active_token_names
                .push("XPATH_INJECTION".to_string());
        }

        // 30. v6 transport/content obfuscation layer.
        if normalized.contains('\u{1b}') {
            tokens.has_ansi_escape = true;
            tokens
                .active_token_names
                .push("ANSI_ESCAPE_SEQUENCE".to_string());
        }
        if RE_NESTED_QUANT.get().unwrap().is_match(&normalized) {
            tokens.has_nested_quantifier = true;
            tokens
                .active_token_names
                .push("REDOS_NESTED_QUANTIFIER".to_string());
        }
        if RE_SAML_PROTO.get().unwrap().is_match(&normalized) {
            tokens.has_saml_protocol = true;
            tokens
                .active_token_names
                .push("SAML_PROTOCOL_MESSAGE".to_string());
        }
        if RE_XSLT.get().unwrap().is_match(&normalized) {
            tokens.has_xslt_stylesheet = true;
            tokens
                .active_token_names
                .push("XSLT_STYLESHEET".to_string());
        }
        if RE_XQUERY.get().unwrap().is_match(&normalized) {
            tokens.has_xquery_expr = true;
            tokens
                .active_token_names
                .push("XQUERY_EXPRESSION".to_string());
        }
        if RE_SMTP_CMD.get().unwrap().is_match(&normalized) {
            tokens.has_smtp_command = true;
            tokens
                .active_token_names
                .push("SMTP_COMMAND_INJECTION".to_string());
        }
        if RE_JSONRPC_EXEC.get().unwrap().is_match(&normalized) {
            tokens.has_jsonrpc_exec = true;
            tokens
                .active_token_names
                .push("RPC_METHOD_ABUSE".to_string());
        }
        if RE_ABS_UPLOAD_PATH.get().unwrap().is_match(&normalized) {
            tokens.has_absolute_upload_path = true;
            tokens
                .active_token_names
                .push("ABSOLUTE_UPLOAD_PATH".to_string());
        }
        // CSV formula: only fires when the text smells like a spreadsheet export
        // context (cell/export/csv/sheet/download), never in arbitrary prose.
        let csv_ctx = norm_lower.contains("cell")
            || norm_lower.contains("export")
            || norm_lower.contains("csv")
            || norm_lower.contains("sheet")
            || norm_lower.contains("download");
        if csv_ctx && RE_CSV_FORMULA.get().unwrap().is_match(&normalized) {
            tokens.has_csv_formula = true;
            tokens
                .active_token_names
                .push("CSV_FORMULA_INJECTION".to_string());
        }
        // Log forging: newline+timestamp/level/stack frame, or forged ANSI paint.
        if RE_LOG_LINE.get().unwrap().is_match(&normalized) {
            tokens.has_log_forgery = true;
            tokens
                .active_token_names
                .push("LOG_LINE_FORGERY".to_string());
        }
        // Invisible tag characters (U+E0000–E007F) and bidi overrides present
        // in the RAW input — after folding they vanish, so evidence must be
        // captured before normalization.
        if raw_text.chars().any(|c| {
            matches!(c,
                '\u{E0000}'..='\u{E007F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200B}'..='\u{200D}'
                | '\u{2060}'
                | '\u{FEFF}')
        }) {
            tokens.has_hidden_chars = true;
            tokens
                .active_token_names
                .push("INVISIBLE_CHAR_SMEUGLING".to_string());
        }
        // Mail-header keys smuggled as JSON fields.
        if RE_MAIL_HDR_JSON.get().unwrap().is_match(&normalized) {
            tokens.has_smtp_command = true;
            tokens
                .active_token_names
                .push("MAIL_HEADER_JSON_INJECTION".to_string());
        }
        // Base64-encoded XML carrying SAML markers (SAMLResponse posted raw).
        if normalized.len() > 200 && RE_B64_XML_SAML.get().unwrap().is_match(&normalized) {
            // Cheap pre-filter: the blob must contain SAML-ish base64 fragments
            // or the PD94bWwg ("<?xml ") prolog in any alignment.
            let low = normalized.to_ascii_lowercase();
            if low.contains("pd94bw") || low.contains("c2ftb") || low.contains("u0fud") {
                tokens.has_saml_protocol = true;
                tokens
                    .active_token_names
                    .push("SAML_BASE64_ASSERTION".to_string());
            }
        }
        // Keyword smuggling: a confusable/homoglyph-folded keyword appearing in
        // the canonical text. Only fires when the raw input was obfuscated AND
        // the keyword sits in a parameter-value position (preceded by '='),
        // so path segments (/wp-admin/) and JSON string values stay benign.
        if is_obfuscated {
            let kw_hit = RE_KEYWORD_SMUGGLE
                .get()
                .unwrap()
                .find_iter(&normalized)
                .any(|m| normalized[..m.start()].trim_end().ends_with('='));
            if kw_hit {
                tokens.has_keyword_smuggling = true;
                tokens
                    .active_token_names
                    .push("CONFUSABLE_KEYWORD_SMEUGGLE".to_string());
            }
        }

        // 31. Data-semantic anomalies (candidate-grade heuristics).
        // Numeric: negative or absurdly large money/quantity fields.
        // NUM_BIG captures the magnitude so canonical 32-bit boundary
        // constants (INT32_MAX=2147483647, UINT32_MAX=4294967295) — legitimate
        // developer test values — do not count as anomalies. 64-bit maxima
        // still fire: no real field legitimately holds u64::MAX.
        let num_big_hit = RE_NUM_BIG
            .get()
            .unwrap()
            .captures(&normalized)
            .map(|c| {
                c.get(1)
                    .and_then(|m| m.as_str().parse::<u128>().ok())
                    .map(|n| !matches!(n, 2_147_483_647 | 4_294_967_295))
                    .unwrap_or(true)
            })
            .unwrap_or(false);
        if RE_NUMERIC_ANOMALY.get().unwrap().is_match(&normalized)
            && (RE_NUM_NEG.get().unwrap().is_match(&normalized)
                || num_big_hit
                || RE_DISCOUNT100.get().unwrap().is_match(&normalized)
                || RE_NUM_TINY.get().unwrap().is_match(&normalized))
        {
            tokens.has_numeric_anomaly = true;
            tokens
                .active_token_names
                .push("NUMERIC_FIELD_ANOMALY".to_string());
        }
        // Privileged fields: key present AND value looks like privilege grant.
        if RE_PRIVILEGED_KEY.get().unwrap().is_match(&normalized)
            && RE_PRIV_VAL.get().unwrap().is_match(&normalized)
        {
            tokens.has_privileged_field = true;
            tokens
                .active_token_names
                .push("PRIVILEGED_FIELD_ASSIGNMENT".to_string());
        }

        tokens.active_token_names.sort();
        tokens.active_token_names.dedup();
        tokens
    }

    /// Full-fidelity HTTP request tokenizer combining headers, body, framing, and AST grammars.
    pub fn tokenize_request(req: &HttpRequestPayload) -> LexicalTokens {
        // Scan every header, not only the whitelisted ones: CRLF injection and
        // framework exploits routinely arrive in custom headers (X-*, Spring
        // function-routing, etc.).
        let mut inspectable = req.full_inspectable_string();
        for (k, v) in &req.headers {
            inspectable.push(' ');
            inspectable.push_str(k);
            inspectable.push_str(": ");
            inspectable.push_str(v);
        }
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
        if gql.has_abuse {
            tokens.has_graphql_abuse = true;
        }
        tokens.active_token_names.extend(gql.active_tokens);

        // B. Strict JSON Schema & Prototype Pollution
        let js = JsonStrictAnalyzer::analyze(&req.body);
        let js_query = JsonStrictAnalyzer::analyze(&req.query_string);
        if js.has_proto_pollution || js_query.has_proto_pollution {
            tokens.has_proto_pollution = true;
        }
        if js.has_deep_nesting || js_query.has_deep_nesting {
            tokens.has_json_deep_nesting = true;
        }
        tokens.active_token_names.extend(js.active_tokens);
        tokens.active_token_names.extend(js_query.active_tokens);

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
        if RE_WORDPRESS_PROBE.get().unwrap().is_match(&path_and_query)
            && !path_and_query
                .to_ascii_lowercase()
                .contains("admin-ajax.php")
        {
            tokens.has_wordpress_probe = true;
            tokens
                .active_token_names
                .push("WORDPRESS_RECON_PROBE".to_string());
        }
        if !tokens.has_wordpress_probe
            && path_and_query.contains("xmlrpc.php")
            && (req.body.contains("methodCall")
                || req.body.contains("wp.get")
                || req.body.contains("system.listMethods")
                || req.body.contains("pingback.ping"))
        {
            tokens.has_wordpress_probe = true;
            tokens
                .active_token_names
                .push("WORDPRESS_RECON_PROBE".to_string());
        }
        if RE_SENSITIVE_EXPOSURE
            .get()
            .unwrap()
            .is_match(&path_and_query)
        {
            tokens.has_sensitive_file_probe = true;
            tokens
                .active_token_names
                .push("SENSITIVE_FILE_EXPOSURE_PROBE".to_string());
        }
        // Appliance/CVE admin endpoints (PAN-OS, FortiGate, ASA, Pulse, Citrix,
        // Exchange, Atlassian, Solr, Nacos, XXL-Job, etc.).
        if RE_APPLIANCE_CVE.get().unwrap().is_match(&path_and_query) {
            tokens.has_sensitive_file_probe = true;
            tokens
                .active_token_names
                .push("APPLIANCE_CVE_ENDPOINT_PROBE".to_string());
        }
        let re_framework = RE_FRAMEWORK_EXPLOIT.get().unwrap();
        if re_framework.is_match(&path_and_query)
            || (!req.body.is_empty() && re_framework.is_match(&req.body))
        {
            tokens.has_framework_exploit_probe = true;
            tokens
                .active_token_names
                .push("FRAMEWORK_EXPLOIT_PAYLOAD".to_string());
        }

        // F. Host / Forwarded header integrity (password-reset & cache poisoning)
        if Self::analyze_host_headers(&req.headers) {
            tokens.has_host_header_anomaly = true;
            tokens
                .active_token_names
                .push("HOST_HEADER_INJECTION".to_string());
        }
        // Method-override headers smuggle privileged verbs (PUT/DELETE/PATCH)
        // past front-end method restrictions; TRACE/CONNECT enable cross-site
        // tracing and tunnel abuse.
        for (k, v) in &req.headers {
            let kl = k.to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "x-http-method-override"
                    | "x-http-method"
                    | "x-method-override"
                    | "x-original-method"
            ) {
                let vl = v.trim().to_ascii_uppercase();
                if matches!(
                    vl.as_str(),
                    "PUT" | "DELETE" | "PATCH" | "TRACE" | "CONNECT" | "DEBUG"
                ) {
                    tokens.has_method_override_abuse = true;
                    tokens
                        .active_token_names
                        .push("METHOD_OVERRIDE_ABUSE".to_string());
                    break;
                }
            }
        }
        // Absolute-URI request targets (GET http://evil/x) smuggle a foreign host
        // into origin-form requests; legitimate only on explicit forward proxies.
        if req.path.starts_with("http://") || req.path.starts_with("https://") {
            tokens.has_host_absolute_uri = true;
            tokens.has_host_header_anomaly = true;
            tokens
                .active_token_names
                .push("ABSOLUTE_URI_HOST".to_string());
        }

        // G. Request smuggling / desync: framing-header contradictions.
        // CL+TE together, malformed CL/TE values, duplicate divergent values,
        // and non-standard underscore header names are all desync surfaces.
        {
            let mut te_present = false;
            let mut cl_values: Vec<String> = Vec::new();
            let mut te_values: Vec<String> = Vec::new();
            let mut odd_framing = false;
            for (k, v) in &req.headers {
                let kl = k.to_ascii_lowercase();
                if kl == "transfer-encoding" {
                    te_present = true;
                    te_values.push(v.clone());
                    // TE must be exactly "chunked" (modulo whitespace). Padded
                    // or obfuscated values desync front/back parsers.
                    if !RE_TE_VALUE.get().unwrap().is_match(v) || v != v.trim() {
                        odd_framing = true;
                    }
                } else if kl == "content-length" {
                    cl_values.push(v.clone());
                    let t = v.trim();
                    if t.is_empty()
                        || !t.bytes().all(|b| b.is_ascii_digit())
                        || (t.len() > 1 && t.starts_with('0'))
                        || t.starts_with('+')
                        || v != v.trim()
                    {
                        odd_framing = true;
                    }
                } else if kl == "transfer_encoding" || kl == "content_length" {
                    odd_framing = true;
                }
            }
            let cl_dup =
                cl_values.len() > 1 && cl_values.iter().any(|v| v.trim() != cl_values[0].trim());
            let te_dup =
                te_values.len() > 1 && te_values.iter().any(|v| v.trim() != te_values[0].trim());
            if (te_present && !cl_values.is_empty()) || odd_framing || cl_dup || te_dup {
                tokens.has_smuggling_desync = true;
                tokens
                    .active_token_names
                    .push("HTTP_DESYNC_FRAMING".to_string());
            }
        }

        // H. WebDAV / non-REST methods reaching REST endpoints.
        {
            let m = req.method.to_ascii_uppercase();
            if matches!(
                m.as_str(),
                "PROPFIND"
                    | "PROPPATCH"
                    | "MKCOL"
                    | "COPY"
                    | "MOVE"
                    | "LOCK"
                    | "UNLOCK"
                    | "SEARCH"
                    | "REPORT"
                    | "ACL"
                    | "BASELINE-CONTROL"
                    | "LABEL"
            ) {
                tokens.has_webdav_method = true;
                tokens
                    .active_token_names
                    .push("WEBDAV_METHOD_ABUSE".to_string());
            }
        }

        // I. Cache deception: account-ish path served with a static-asset
        // extension (cache keys on extension, app keys on auth).
        {
            let p = req.path.to_ascii_lowercase();
            if RE_WEBASSET_EXT.get().unwrap().is_match(&p)
                && RE_ACCT_PATH.get().unwrap().is_match(&p)
            {
                tokens.has_cache_deception = true;
                tokens
                    .active_token_names
                    .push("CACHE_DECEPTION_PATH".to_string());
            }
        }

        // J. OAuth/OIDC redirect_uri abuse: userinfo tricks, protocol-relative,
        // javascript:/data: schemes, backslashes.
        {
            let hay = format!("{}?{}", req.path, req.query_string);
            if let Some(re) = RE_REDIRECT_URI.get() {
                for cap in re.captures_iter(&hay) {
                    let val = cap.get(1).map(|m| m.as_str()).unwrap_or("");
                    let vl = val.to_ascii_lowercase();
                    if vl.contains('@')
                        || vl.starts_with("//")
                        || vl.contains("javascript:")
                        || vl.contains("data:")
                        || vl.contains('\\')
                        || vl.contains("%2f%2f")
                    {
                        tokens.has_oauth_redirect_abuse = true;
                        tokens
                            .active_token_names
                            .push("OAUTH_REDIRECT_URI_ABUSE".to_string());
                        break;
                    }
                }
            }
            // ROPC/password grant with elevated scope.
            let ql = req.query_string.to_ascii_lowercase();
            let bl = req.body.to_ascii_lowercase();
            if (ql.contains("grant_type=password") || bl.contains("grant_type=password"))
                && (ql.contains("scope=admin")
                    || bl.contains("scope=admin")
                    || ql.contains("scope=*admin")
                    || bl.contains("scope=*admin"))
            {
                tokens.has_oauth_redirect_abuse = true;
                tokens
                    .active_token_names
                    .push("OAUTH_SCOPE_ESCALATION".to_string());
            }
        }

        // K. IDN homograph / punycode: xn-- hosts inside URL-ish params, or
        // brand names written with Cyrillic lookalikes.
        {
            let pq = format!("{}?{}", req.path, req.query_string);
            let raw_l = pq.to_ascii_lowercase();
            let brand = RE_BRAND_HOST.get().unwrap();
            let cyr = RE_CYR_BRAND.get().unwrap();
            // Param-context punycode: url=/host=/redirect=/link=/to=/callback=
            let urlish = raw_l.contains("url=")
                || raw_l.contains("host=")
                || raw_l.contains("redirect")
                || raw_l.contains("link=")
                || raw_l.contains("to=")
                || raw_l.contains("callback=")
                || raw_l.contains("return=");
            if (raw_l.contains("xn--") && (urlish || brand.is_match(&raw_l)))
                || (cyr.is_match(&pq) && raw_l.contains('.'))
            {
                tokens.has_punycode_host = true;
                tokens
                    .active_token_names
                    .push("PUNYCODE_HOMOGRAPH_HOST".to_string());
            }
        }

        // L. SAML endpoint probing: /saml metadata/login/acs paths are the
        // assertion-receiving surface; unsigned or wrapped assertions arrive
        // here. Deployments with real SAML can disable the island.
        {
            let pl = req.path.to_ascii_lowercase();
            if pl.contains("/saml") || pl.contains("/sso/saml") {
                tokens.has_saml_protocol = true;
                tokens
                    .active_token_names
                    .push("SAML_ENDPOINT_PROBE".to_string());
            }
        }

        // M. SOAPAction header abuse: wildcard actions, exec/admin keywords,
        // or non-HTTP schemes smuggled into the action URI.
        for (k, v) in &req.headers {
            if k.eq_ignore_ascii_case("soapaction") {
                let vl = v.trim().to_ascii_lowercase();
                let suspicious = vl == "*"
                    || vl.contains("javascript:")
                    || vl.contains("data:")
                    || vl.contains("exec")
                    || vl.contains("admin")
                    || vl.contains("shell")
                    || vl.contains("cmd")
                    || vl.contains("system")
                    || vl.contains("upload")
                    || vl.contains("delete")
                    || vl.contains("invoke");
                if suspicious {
                    tokens.has_soap_action_abuse = true;
                    tokens
                        .active_token_names
                        .push("SOAP_ACTION_ABUSE".to_string());
                    break;
                }
            }
        }

        // N. PUT with server-side script body = WebDAV-style write abuse even
        // though PUT alone is a legitimate REST verb.
        if req.method.eq_ignore_ascii_case("PUT")
            && (req.body.contains("<?php")
                || req.body.contains("<?=")
                || req.body.contains("<jsp:")
                || req.body.contains("<%"))
        {
            tokens.has_malicious_upload = true;
            tokens
                .active_token_names
                .push("WEBDAV_SCRIPT_WRITE".to_string());
        }

        // O. Cache poisoning via unkeyed inputs: forwarding headers a shared
        // cache may not key on, or cache-buster params. X-Forwarded-Host is
        // excluded (host-header rules own it; benign when it mirrors Host),
        // utm_* excluded (marketing URLs), Accept-Encoding/Range excluded
        // (legitimate content negotiation).
        for (k, _) in &req.headers {
            if matches!(
                k.to_ascii_lowercase().as_str(),
                "x-forwarded-scheme" | "x-forwarded-port" | "x-original-url" | "x-rewrite-url"
            ) {
                tokens.has_cache_poisoning_signal = true;
                tokens
                    .active_token_names
                    .push("CACHE_POISONING_UNKEYED_INPUT".to_string());
                break;
            }
        }
        if !tokens.has_cache_poisoning_signal {
            for kv in req.query_string.to_ascii_lowercase().split(['&', ';']) {
                let key = kv.split('=').next().unwrap_or("").trim();
                if matches!(key, "cb" | "cachebuster" | "cache_bust" | "nocache" | "_") {
                    tokens.has_cache_poisoning_signal = true;
                    tokens
                        .active_token_names
                        .push("CACHE_POISONING_UNKEYED_INPUT".to_string());
                    break;
                }
            }
        }

        // P. OAuth/OIDC flow anomalies — structural protocol semantics, not
        // payload patterns: an authorize request without `state` (CSRF-able
        // flow) or a token request carrying `redirect_uri` (parameter belongs
        // to the authorize step; its presence signals flow confusion).
        {
            let pl = req.path.to_ascii_lowercase();
            let ql = req.query_string.to_ascii_lowercase();
            let bl = req.body.to_ascii_lowercase();
            let has = |needle: &str| ql.contains(needle) || bl.contains(needle);
            let authorize_ep =
                pl.contains("authorize") || pl.contains("/oauth") || pl.contains("/oidc");
            let token_ep = pl.contains("/token") || pl.contains("/oidc/token");
            let anomaly =
                (authorize_ep && has("redirect_uri=") && has("response_type=") && !has("state="))
                    || (token_ep && has("grant_type=authorization_code") && has("redirect_uri="));
            if anomaly {
                tokens.has_oauth_oidc_signal = true;
                tokens
                    .active_token_names
                    .push("OAUTH_FLOW_ANOMALY".to_string());
            }
        }

        // Q. Mixed-script evasion: a single alphanumeric token blending Latin
        // with Cyrillic/Greek lookalikes (paуссword, admин). Legit bilingual
        // text keeps scripts in separate tokens; requiring a value-ish prefix
        // (= : " ' & ? ; ( [ ,) keeps prose mentions benign.
        for m in RE_MIXED_TOKEN.get().unwrap().find_iter(&inspectable) {
            let tok = m.as_str();
            let has_latin = tok.bytes().any(|b| b.is_ascii_alphabetic());
            let has_nonascii = tok.chars().any(|c| !c.is_ascii());
            if !(has_latin && has_nonascii && tok.chars().count() >= 4) {
                continue;
            }
            let preceded = inspectable[..m.start()]
                .chars()
                .last()
                .map(|c| {
                    matches!(
                        c,
                        '=' | ':' | '"' | '\'' | '&' | '?' | ';' | '(' | '[' | ','
                    )
                })
                .unwrap_or(true);
            if preceded {
                tokens.has_unicode_normalization_signal = true;
                tokens
                    .active_token_names
                    .push("MIXED_SCRIPT_EVASION".to_string());
                break;
            }
        }

        // R/S/T. Parameter-pair analyzers over the normalized request: they
        // see query strings and JSON bodies in one canonical form.
        {
            let norm = tokens.normalized_text.clone();
            let mut param_abs_path = false;
            let mut cms_probe = false;
            let mut benefits: Vec<f64> = Vec::new();
            let mut ceilings: Vec<f64> = Vec::new();
            for cap in RE_PARAM_PAIR.get().unwrap().captures_iter(&norm) {
                let key = cap[1].to_ascii_lowercase();
                let val = cap[2].to_ascii_lowercase();
                // R. Absolute/traversal path values in non-file params. An
                // absolute path alone is benign (C:\temp\file.txt, /etc/hosts,
                // /var/www/htdocs are legitimate references) — it only signals
                // LFI/archive-slip when the target is executable, a sensitive
                // file, or a log file under /var/log.
                if !param_abs_path {
                    let abs_sensitive = val.starts_with("/etc/")
                        || val.starts_with("/var/")
                        || val.starts_with("/proc/")
                        || val.starts_with("/root/")
                        || val.starts_with("/boot/")
                        || val.starts_with("/dev/")
                        || val.starts_with("/sys/");
                    let win_drive = val.len() >= 3
                        && val.as_bytes()[0].is_ascii_alphabetic()
                        && val.as_bytes()[1] == b':'
                        && (val.as_bytes()[2] == b'\\' || val.as_bytes()[2] == b'/');
                    if abs_sensitive || win_drive {
                        let dangerous_ext = val.ends_with(".php")
                            || val.ends_with(".jsp")
                            || val.ends_with(".asp")
                            || val.ends_with(".aspx")
                            || val.ends_with(".sh")
                            || val.ends_with(".dll")
                            || val.ends_with(".exe")
                            || val.ends_with(".py")
                            || val.ends_with(".pl")
                            || val.ends_with(".cgi")
                            || val.ends_with(".ps1")
                            || val.ends_with(".bat")
                            || val.ends_with(".cmd")
                            || val.ends_with(".vbs")
                            || val.ends_with(".wsf");
                        let sensitive_base = val.contains("passwd")
                            || val.contains("shadow")
                            || val.contains("wp-config")
                            || val.contains(".env")
                            || val.contains("id_rsa")
                            || val.contains("id_dsa")
                            || val.contains("web.config")
                            || val.contains("boot.ini")
                            || val.contains(".git/");
                        let log_target = val.contains("/var/log/") && val.ends_with(".log");
                        if dangerous_ext || sensitive_base || log_target || val.contains("..") {
                            param_abs_path = true;
                        }
                    }
                    let trav_sensitive = val.contains("..")
                        && (val.contains("wp-config")
                            || val.contains(".env")
                            || val.contains("id_rsa")
                            || val.contains("shadow")
                            || val.contains("passwd")
                            || val.contains(".git")
                            || val.contains("web.config")
                            || val.contains("boot.ini"));
                    if trav_sensitive {
                        param_abs_path = true;
                    }
                }
                // S. CMS action params naming vulnerable plugin slugs.
                if !cms_probe
                    && matches!(
                        key.as_str(),
                        "action" | "do" | "task" | "operation" | "plugin" | "module"
                    )
                    && RE_CMS_VULN_SLUG.get().unwrap().is_match(&val)
                {
                    cms_probe = true;
                }
                // T. Cross-param numeric anomaly: benefit fields (gamification
                // currency) vs declared ceilings (max*/limit/cap/...)
                if let Ok(n) = val
                    .trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
                    .parse::<f64>()
                {
                    if matches!(
                        key.as_str(),
                        "bonus"
                            | "score"
                            | "points"
                            | "credit"
                            | "tip"
                            | "gift"
                            | "reward"
                            | "coins"
                            | "winnings"
                            | "payout"
                            | "cashback"
                            | "rebate"
                            | "jackpot"
                            | "multiplier"
                            | "xp"
                    ) {
                        benefits.push(n);
                    } else if key.starts_with("max")
                        || matches!(
                            key.as_str(),
                            "limit" | "limits" | "cap" | "caps" | "ceiling" | "bound" | "threshold"
                        )
                    {
                        ceilings.push(n);
                    }
                }
            }
            if param_abs_path {
                tokens.has_path_traversal_signal = true;
                tokens
                    .active_token_names
                    .push("PARAM_ABS_PATH_TRAVERSAL".to_string());
            }
            if cms_probe {
                tokens.has_cms_wordpress_probe_signal = true;
                tokens
                    .active_token_names
                    .push("CMS_PLUGIN_PROBE_ACTION".to_string());
            }
            // benefit >= 100 AND exceeds every ceiling by >50x
            if benefits
                .iter()
                .any(|&b| b >= 100.0 && ceilings.iter().any(|&c| b > c.abs() * 50.0 + f64::EPSILON))
            {
                tokens.has_business_logic_signal = true;
                tokens
                    .active_token_names
                    .push("CROSS_PARAM_NUMERIC_ANOMALY".to_string());
            }
        }

        // U. v7 lex proposals — parameter-level semantic anomalies.
        {
            let norm = tokens.normalized_text.clone();
            let mut dup_keys: std::collections::HashMap<
                String,
                std::collections::BTreeSet<String>,
            > = std::collections::HashMap::new();
            let mut bracket_keys: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            let mut bracket_keys_all: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            let mut magic_hash = false;
            let mut hex_juggle = false;
            let mut proto_inject = false;
            let mut webhook_ssrf = false;
            let mut open_redirect = false;
            let mut int_overflow = false;
            let mut classloader = false;

            const SENSITIVE_KEYS: &[&str] = &[
                "username",
                "user",
                "password",
                "passwd",
                "pass",
                "pwd",
                "email",
                "token",
                "role",
                "admin",
                "account",
                "login",
                "auth",
                "secret",
                "key",
                "permission",
                "permissions",
                "isadmin",
                "verified",
                "credit",
                "balance",
                "price",
                "amount",
                "qty",
                "quantity",
                "bid",
                "score",
                "bonus",
                "discount",
            ];
            const REDIRECT_KEYS: &[&str] = &[
                "next",
                "redirect",
                "return",
                "url",
                "to",
                "target",
                "continue",
                "continue_url",
                "redir",
                "go",
                "link",
                "out",
                "u",
                "return_url",
                "returnto",
                "return_to",
                "dest",
                "destination",
                "redirect_url",
                "redirect_uri",
                "redirect_to",
                "forward",
                "goto",
            ];
            const WEBHOOK_KEYS: &[&str] = &[
                "callback",
                "webhook",
                "webhook_url",
                "notify_url",
                "notify",
                "pingback",
                "endpoint",
                "delivery",
                "callback_url",
                "target_url",
                "hook",
                "feed_url",
                "notify_uri",
                "call_back",
            ];
            const JUGGLE_KEYS: &[&str] = &[
                "password",
                "passwd",
                "pass",
                "pwd",
                "token",
                "hash",
                "secret",
                "key",
                "auth",
                "signature",
                "nonce",
                "code",
                "digest",
                "apikey",
                "api_key",
                "session",
                "sess",
                "jwt",
                "credential",
                "id",
                "num",
                "n",
                "qty",
                "count",
                "level",
                "pin",
                "otp",
                "year",
                "month",
                "day",
                "version",
                "build",
            ];
            const BIG_NUM_KEYS: &[&str] = &[
                "percent",
                "ratio",
                "multiplier",
                "factor",
                "count",
                "num",
                "number",
                "percentage",
            ];

            for cap in RE_PARAM_PAIR.get().unwrap().captures_iter(&norm) {
                let key = cap[1].to_ascii_lowercase();
                let val = cap[2].to_string();
                let vl = val.to_ascii_lowercase();
                if !val.is_empty() {
                    dup_keys.entry(key.clone()).or_default().insert(val.clone());
                }
                if !magic_hash
                    && JUGGLE_KEYS.contains(&key.as_str())
                    && RE_MAGIC_HASH.get().unwrap().is_match(&vl)
                {
                    magic_hash = true;
                }
                if !hex_juggle
                    && JUGGLE_KEYS.contains(&key.as_str())
                    && RE_HEX_NUM.get().unwrap().is_match(&vl)
                {
                    hex_juggle = true;
                }
                if !proto_inject && (vl.contains('\n') || vl.contains('\r') || vl.contains('+')) {
                    // Wide pass below sees the full value including CRLF.
                }
                if !webhook_ssrf
                    && WEBHOOK_KEYS.contains(&key.as_str())
                    && RE_INTERNAL_HOST.get().unwrap().is_match(&vl)
                {
                    webhook_ssrf = true;
                }
                if !open_redirect && REDIRECT_KEYS.contains(&key.as_str()) {
                    // Judge on the DECODED value: %2f%2f at value start means
                    // protocol-relative //evil, while %3A%2F%2F is just an
                    // https:// URL — the raw variant still holds the literal
                    // escapes, so checking vl alone would FP on encoded URLs.
                    let dvl = percent_decode_str(&val).decode_utf8_lossy().to_lowercase();
                    if vl.starts_with("//")
                        || dvl.starts_with("//")
                        || dvl.contains("javascript:")
                        || dvl.contains("data:")
                        || dvl.contains("\\\\")
                    {
                        open_redirect = true;
                    }
                }
                // Integer overflow: >u64::MAX all-digit values, |exp|>=30
                // scientific notation, or extended big-number keys >= 1e6.
                if !int_overflow {
                    if val.bytes().all(|b| b.is_ascii_digit()) && val.len() >= 19 {
                        if let Ok(n) = val.parse::<u128>() {
                            if n > u64::MAX as u128 {
                                int_overflow = true;
                            }
                        }
                    }
                    // Scientific notation only overflows when the value is
                    // actually unrepresentable — 0e999 parses to 0.0 (benign
                    // magic-hash shape), 1e309 parses to f64::INFINITY.
                    if vl.parse::<f64>().map(|f| f.is_infinite()).unwrap_or(false) {
                        int_overflow = true;
                    }
                    if BIG_NUM_KEYS.contains(&key.as_str()) {
                        if let Ok(n) = vl.trim().parse::<f64>() {
                            if n.abs() >= 1_000_000.0 {
                                int_overflow = true;
                            }
                        }
                    }
                }
            }
            // Spring4Shell binding keys can exceed the pair-regex key limit
            // (~58 chars), so check the normalized text for the
            // classloader+pipeline signature directly.
            if !classloader {
                let nl = norm.to_ascii_lowercase();
                if nl.contains("classloader")
                    && (nl.contains("pipeline")
                        || nl.contains("class.module")
                        || nl.contains(".first."))
                {
                    classloader = true;
                }
            }
            // Protocol injection needs values that may contain CRLF, which the
            // narrow pair regex truncates at \s — use the wide variant here.
            if !proto_inject {
                const ALONE_PROTO: &[&str] = &[
                    "eval",
                    "config",
                    "flushall",
                    "flushdb",
                    "flush_all",
                    "slaveof",
                    "replicaof",
                    "psync",
                    "replconf",
                    "slowlog",
                    "asking",
                    "failover",
                    "migrate",
                    "monitor",
                    "subscribe",
                    "psubscribe",
                    "pubsub",
                    "shutdown",
                ];
                for cap in RE_PARAM_PAIR_WIDE.get().unwrap().captures_iter(&norm) {
                    let vl = cap[2].to_ascii_lowercase();
                    let vl_sp = vl.replace('+', " ");
                    let has_nl = vl.contains('\n') || vl.contains('\r');
                    if has_nl && RE_PROTO_LINE.get().unwrap().is_match(&vl_sp) {
                        proto_inject = true;
                        break;
                    }
                    // Dangerous-alone verbs (never legit param values) fire
                    // when followed by arguments or a CRLF payload.
                    let first = vl_sp.split_whitespace().next().unwrap_or("");
                    if ALONE_PROTO.contains(&first)
                        && (has_nl || vl_sp.split_whitespace().count() >= 2)
                    {
                        proto_inject = true;
                        break;
                    }
                    // Inline memcached/redis verb without CRLF: argument must
                    // look protocol-ish (/, :, RESP marker, or digit run).
                    if !has_nl {
                        if let Some(m) = RE_INLINE_PROTO.get().unwrap().find(&vl_sp) {
                            let _ = m;
                            let rest = vl_sp[m.end()..].trim_start();
                            if rest.contains('/')
                                || rest.contains(':')
                                || rest.contains('*')
                                || rest.contains('$')
                                || rest
                                    .split_whitespace()
                                    .any(|w| w.len() >= 4 && w.bytes().all(|b| b.is_ascii_digit()))
                            {
                                proto_inject = true;
                                break;
                            }
                        }
                    }
                }
            }
            // Bracket-array params: sensitive keys (type juggling) and
            // divergent values under one base key (pollution).
            for cap in RE_BRACKET_PARAM.get().unwrap().captures_iter(&norm) {
                let key = cap[1].to_ascii_lowercase();
                let val = cap[2].to_string();
                if SENSITIVE_KEYS.contains(&key.as_str()) {
                    bracket_keys
                        .entry(key.clone())
                        .or_default()
                        .push(val.clone());
                }
                // Pollution view: ANY bracket base key repeating with divergent
                // values — privilege flavor decides, not key sensitivity.
                bracket_keys_all.entry(key).or_default().push(val);
            }
            // v86 pollution: same scalar key, >=2 distinct values, at least
            // one privilege/conflict-flavored value.
            let pollution = dup_keys.iter().any(|(_, vals)| {
                vals.len() > 1
                    && vals
                        .iter()
                        .any(|v| RE_PRIV_LIKE_VALUE.get().unwrap().is_match(v))
            }) || bracket_keys_all.values().any(|vals| {
                let distinct: std::collections::BTreeSet<&String> = vals.iter().collect();
                distinct.len() > 1
                    && vals
                        .iter()
                        .any(|v| RE_PRIV_LIKE_VALUE.get().unwrap().is_match(v))
            });
            if pollution {
                tokens.has_parameter_pollution_signal = true;
                tokens
                    .active_token_names
                    .push("PARAM_VALUE_POLLUTION".to_string());
            }
            if magic_hash || hex_juggle || !bracket_keys.is_empty() {
                tokens.has_type_juggling_signal = true;
                tokens
                    .active_token_names
                    .push("LOOSE_TYPE_JUGGLING".to_string());
            }
            if proto_inject {
                tokens.has_protocol_injection_signal = true;
                tokens
                    .active_token_names
                    .push("REDIS_MEMCACHED_INJECTION".to_string());
            }
            if webhook_ssrf {
                tokens.has_webhook_ssrf_signal = true;
                tokens
                    .active_token_names
                    .push("WEBHOOK_CALLBACK_SSRF".to_string());
            }
            if open_redirect {
                tokens.has_open_redirect_signal = true;
                tokens
                    .active_token_names
                    .push("OPEN_REDIRECT_PARAM".to_string());
            }
            if int_overflow {
                tokens.has_integer_overflow_signal = true;
                tokens
                    .active_token_names
                    .push("INTEGER_OVERFLOW_BOUNDARY".to_string());
            }
            if classloader {
                tokens.has_spring4shell_signal = true;
                tokens
                    .active_token_names
                    .push("CLASSLOADER_BINDING_INJECTION".to_string());
            }
        }

        // V. Request-level signals: CONNECT tunneling, HTTP/2 pseudo-headers,
        // management endpoints, Content-Type confusion, WebSocket abuse.
        if req.method.eq_ignore_ascii_case("CONNECT") {
            tokens.has_connect_tunnel_signal = true;
            tokens
                .active_token_names
                .push("CONNECT_TUNNEL_ABUSE".to_string());
        }
        for (k, _) in &req.headers {
            if k.starts_with(':') {
                tokens.has_http2_pseudo_header = true;
                tokens
                    .active_token_names
                    .push("HTTP2_PSEUDO_HEADER_LEAK".to_string());
                break;
            }
        }
        {
            let pq = format!("{}?{}", req.path, req.query_string).to_ascii_lowercase();
            if RE_MGMT_ENDPOINT.get().unwrap().is_match(&pq) {
                tokens.has_management_endpoint_signal = true;
                tokens
                    .active_token_names
                    .push("MANAGEMENT_ENDPOINT_PROBE".to_string());
            }
            // WebSocket upgrade carrying injection-flavored subprotocols.
            let is_ws = req.headers.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket")
            });
            if is_ws {
                for (k, v) in &req.headers {
                    if k.eq_ignore_ascii_case("sec-websocket-protocol") {
                        let vl = v.to_ascii_lowercase();
                        if vl.contains("sql")
                            || vl.contains("script")
                            || vl.contains("exec")
                            || vl.contains("eval")
                            || vl.contains("admin")
                            || vl.contains("..")
                            || vl.contains('<')
                            || vl.contains("javascript")
                        {
                            tokens.has_websocket_abuse_signal = true;
                            tokens
                                .active_token_names
                                .push("WEBSOCKET_SUBPROTOCOL_ABUSE".to_string());
                            break;
                        }
                    }
                }
            }
            // Content-Type confusion: declared type contradicts body shape.
            let ct = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_ascii_lowercase());
            if let Some(ct) = ct {
                let body_t = req.body.trim_start();
                let first = body_t.chars().next().unwrap_or(' ');
                let body_json = first == '{' || first == '[';
                let body_xml = first == '<';
                let body_form = RE_FORM_BODY.get().unwrap().is_match(body_t);
                let json_ct = ct.contains("json");
                let xml_ct = ct.contains("xml");
                let form_ct = ct.contains("x-www-form-urlencoded");
                if (json_ct && (body_xml || body_form))
                    || (xml_ct && (body_json || body_form))
                    || (form_ct && (body_json || body_xml))
                {
                    tokens.has_content_type_confusion_signal = true;
                    tokens
                        .active_token_names
                        .push("CONTENT_TYPE_CONFUSION".to_string());
                }
            }
        }

        // W. CRS rule-group coverage: language-runtime abuse classes that the
        // payload-oriented islands do not model (Java/.NET runtimes, DBMS-
        // specific functions, Windows cmd, PHP/Node sinks, ORM lookups).
        {
            let norm = tokens.normalized_text.to_ascii_lowercase();
            if RE_JAVA_ATTACK.get().unwrap().is_match(&norm) {
                tokens.has_java_attack_signal = true;
                tokens
                    .active_token_names
                    .push("JAVA_RUNTIME_ABUSE".to_string());
            }
            if RE_JAVA_GADGET.get().unwrap().is_match(&norm) {
                tokens.has_java_deserialization_signal = true;
                tokens
                    .active_token_names
                    .push("JAVA_DESERIALIZATION_GADGET".to_string());
            }
            if RE_JAVA_SINK.get().unwrap().is_match(&norm) {
                tokens.has_java_runtime_sink = true;
                tokens
                    .active_token_names
                    .push("JAVA_RUNTIME_SINK".to_string());
            }
            if RE_DATA_URI_MARKUP.get().unwrap().is_match(&norm) {
                tokens.has_xss_extended_signal = true;
                tokens
                    .active_token_names
                    .push("DATA_URI_MARKUP".to_string());
            }
            if RE_SQL_EXTENDED.get().unwrap().is_match(&norm)
                || RE_SQL_TAUTOLOGY.get().unwrap().is_match(&norm)
                || RE_ORM_LOOKUP.get().unwrap().is_match(&norm)
            {
                tokens.has_sqli_extended_signal = true;
                tokens
                    .active_token_names
                    .push("EXTENDED_INJECTION_PRIMITIVE".to_string());
            }
            if RE_RCE_EXTENDED.get().unwrap().is_match(&norm) {
                tokens.has_rce_extended_signal = true;
                tokens
                    .active_token_names
                    .push("WINDOWS_CMD_CONSTRUCT".to_string());
            }
            // _method= verb tunneling applies to query string AND body params.
            let pq_body = format!("{} {}", req.query_string, req.body);
            if RE_METHOD_OVERRIDE_PARAM
                .get()
                .unwrap()
                .is_match(&pq_body.to_ascii_lowercase())
            {
                tokens.has_protocol_enforcement_signal = true;
                tokens
                    .active_token_names
                    .push("METHOD_OVERRIDE_TUNNEL".to_string());
            }
            if RE_PHP_DANGER.get().unwrap().is_match(&norm)
                || RE_PHP_VAR_SHAPE.get().unwrap().is_match(&norm)
                || RE_PHP_INI_KEY.get().unwrap().is_match(&norm)
            {
                tokens.has_php_injection_signal = true;
                tokens
                    .active_token_names
                    .push("PHP_RUNTIME_SINK".to_string());
            }
            if RE_NODEJS_ABUSE.get().unwrap().is_match(&norm) {
                tokens.has_nodejs_injection_signal = true;
                tokens
                    .active_token_names
                    .push("NODEJS_RUNTIME_ABUSE".to_string());
            }
            if RE_XSS_EXTENDED.get().unwrap().is_match(&norm) {
                tokens.has_xss_extended_signal = true;
                tokens
                    .active_token_names
                    .push("JS_RUNTIME_SINK".to_string());
            }
            let mut lfi_ext = RE_LFI_EXTENDED.get().unwrap().is_match(&norm);
            // AI-tool / editor dot-directories absent from RE_SENSITIVE_EXPOSURE.
            let low_path = req.path.to_ascii_lowercase();
            if !lfi_ext
                && [
                    "/.codex",
                    "/.opencode",
                    "/.cursor",
                    "/.claude",
                    "/.aider",
                    "/.continue",
                    "/.cody",
                    "/.tabnine",
                    "/.codeium",
                    "/.windsurf",
                    "/.amazonq",
                    "/.kiro",
                    "/.trae",
                    "/.void",
                    "/.config/gh",
                    "/.config/gcloud",
                    "/.azure",
                    "/.config/hub",
                ]
                .iter()
                .any(|p| low_path.contains(p))
            {
                lfi_ext = true;
                tokens.has_sensitive_file_probe = true;
            }
            if lfi_ext {
                tokens.has_lfi_extended_signal = true;
                tokens
                    .active_token_names
                    .push("EXTENDED_PATH_ABUSE".to_string());
            }
            if RE_RFI_SCHEME.get().unwrap().is_match(&norm) {
                tokens.has_rfi_scheme_signal = true;
                tokens
                    .active_token_names
                    .push("NONHTTP_URL_SCHEME".to_string());
            }
            // Session identifiers in the URL query only — bodies legitimately
            // carry sessionid on login forms.
            if RE_SESSION_URL
                .get()
                .unwrap()
                .is_match(&req.query_string.to_ascii_lowercase())
            {
                tokens.has_session_token_url_signal = true;
                tokens
                    .active_token_names
                    .push("SESSION_ID_IN_URL".to_string());
            }
            // Protocol enforcement: exotic charset declarations, request-line
            // smuggling inside params, invalid HTTP method tokens, Range
            // header fan-out (multi-range DoS / desync aid).
            if RE_BAD_CHARSET.get().unwrap().is_match(&norm)
                || RE_ABS_URI_METHOD.get().unwrap().is_match(&norm)
            {
                tokens.has_protocol_enforcement_signal = true;
                tokens
                    .active_token_names
                    .push("PROTOCOL_DIFFERENTIAL".to_string());
            }
            {
                // HTTP method must be a token of reasonable length; pipelines
                // and unknown verbs beyond that are enforcement failures.
                let m = req.method.as_bytes();
                let valid_token = m
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b));
                if !valid_token || m.len() > 20 {
                    tokens.has_protocol_enforcement_signal = true;
                    tokens
                        .active_token_names
                        .push("INVALID_METHOD_TOKEN".to_string());
                }
                for (k, v) in &req.headers {
                    let kl = k.to_ascii_lowercase();
                    let vl_h = v.to_ascii_lowercase();
                    // request-range is non-standard: ANY bytes= range on it is
                    // suspicious; Range needs fan-out (>=5 ranges) to count.
                    if (kl == "request-range" && vl_h.contains("bytes="))
                        || (kl == "range"
                            && vl_h.starts_with("bytes=")
                            && vl_h.matches(',').count() >= 5)
                        || v.contains(",,,")
                    {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("RANGE_FANOUT_ABUSE".to_string());
                        break;
                    }
                    // A header whose ENTIRE value is a bare shell command
                    // (user-agent: id / referer: whoami) is a probe, not traffic.
                    {
                        let t = v.trim().to_ascii_lowercase();
                        if matches!(
                            t.as_str(),
                            "id" | "whoami"
                                | "uname"
                                | "pwd"
                                | "ls"
                                | "cat"
                                | "env"
                                | "printenv"
                                | "ifconfig"
                                | "netstat"
                                | "ps"
                                | "w"
                                | "last"
                                | "uptime"
                                | "df"
                                | "free"
                                | "hostname"
                                | "tty"
                                | "groups"
                                | "users"
                                | "set"
                                | ";set"
                                | "-c"
                                | "--help"
                                | "-v"
                                | "--version"
                        ) {
                            tokens.has_rce_extended_signal = true;
                            tokens
                                .active_token_names
                                .push("BARE_COMMAND_HEADER".to_string());
                        }
                    }
                    // OGNL/template markers or multipart/related smuggled into
                    // Content-Type.
                    if kl == "content-type"
                        && (vl_h.contains("%{")
                            || vl_h.contains("#{")
                            || vl_h.contains("multipart/related"))
                    {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("CONTENT_TYPE_CONFUSION".to_string());
                    }
                    // Script-extension filenames smuggled in custom upload
                    // headers (X-Filename etc.) — the body filename= rules
                    // never see these.
                    if (kl.contains("filename") || kl.contains("file-name") || kl == "x-file")
                        && RE_SCRIPT_EXT_HDR.get().unwrap().is_match(v)
                    {
                        tokens.has_malicious_upload = true;
                        tokens
                            .active_token_names
                            .push("SCRIPT_EXT_HEADER".to_string());
                    }
                    // Empty mandatory-ish headers are parser-differential bait.
                    if (kl == "user-agent" || kl == "accept") && v.trim().is_empty() {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("EMPTY_MANDATORY_HEADER".to_string());
                    }
                    // boundary= is only legal on multipart/* — elsewhere it is
                    // a parser-differential / smuggling probe.
                    if kl == "content-type"
                        && v.to_ascii_lowercase().contains("boundary")
                        && !v.to_ascii_lowercase().contains("multipart")
                    {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("BOUNDARY_ON_NONMULTIPART".to_string());
                    }
                }
                // HTML-entity fragments inside multipart field names
                // (name="amp;zzz") — parser differentials between proxies.
                if RE_MULTIPART_BAD_FN.get().unwrap().is_match(&req.body)
                    || (req.body.contains("name=\"")
                        && RE_ENTITY_NAME.get().unwrap().is_match(&req.body))
                {
                    tokens.has_malicious_upload = true;
                    tokens
                        .active_token_names
                        .push("MULTIPART_NAME_ABUSE".to_string());
                }
            }
            // JSON keys carrying SQL vocabulary.
            if RE_JSON_KEY_SQL.get().unwrap().is_match(&norm) {
                tokens.has_sqli_extended_signal = true;
                tokens
                    .active_token_names
                    .push("JSON_KEY_SQL_INJECTION".to_string());
            }
            // Reflected database error strings inside request bodies.
            if RE_SQL_ERROR_MSG.get().unwrap().is_match(&norm) {
                tokens.has_sqli_extended_signal = true;
                tokens
                    .active_token_names
                    .push("SQL_ERROR_REFLECTION".to_string());
            }
            // Null bytes and adjacent 0xHH hex-pair runs (truncation / encoded
            // traversal shapes like 0x5c0x2e.%00/).
            if norm.contains('\0') || RE_HEX_PAIRS.get().unwrap().is_match(&norm) {
                tokens.has_lfi_extended_signal = true;
                tokens
                    .active_token_names
                    .push("NULL_BYTE_OR_HEX_TRAVERSAL".to_string());
            }
            // Base64-encoded Java gadget vocabulary (CRS 944xxx ships class
            // names base64'd inside params). Decode candidates and substring-
            // match against the gadget lexicon — bounded scan for latency.
            {
                const GADGETS: &[&str] = &[
                    "processbuilder",
                    "getruntime",
                    "classloader",
                    "invokertransformer",
                    "instantiate",
                    "templatesimpl",
                    "jdbcrowset",
                    "xstream",
                    "fastjson",
                    "snakeyaml",
                    "aspectj",
                    "javassist",
                    "ognl",
                    "spel",
                    "mvel",
                    "groovy",
                    "rhino",
                    "jython",
                    "beanshell",
                    "opensymphony",
                    "springframework",
                    "readobject",
                    "serialversionuid",
                    "scriptenginemanager",
                    "urlclassloader",
                    "forclosure",
                    "instantiate",
                    "annotationinvocationhandler",
                ];
                // Common English/Java words that only count alongside a
                // dotted class-name shape (com.foo.Transformer), not prose.
                const WEAK_GADGETS: &[&str] = &[
                    "transformer",
                    "accessor",
                    "converter",
                    "memberaccess",
                    "chained",
                    "constant",
                    "closure",
                    "factory",
                    "prototype",
                    "clone",
                    "comparator",
                    "priorityqueue",
                    "hashmap",
                    "hashtable",
                    "hashset",
                    "treemap",
                    "linkedhash",
                    "jdk.proxy",
                ];
                let mut scanned = 0usize;
                for cap in RE_B64_TOKEN
                    .get()
                    .unwrap()
                    .captures_iter(&tokens.normalized_text)
                {
                    scanned += 1;
                    if scanned > 300 {
                        break;
                    }
                    let tok = &cap[1];
                    if tok.len() < 12 {
                        continue;
                    }
                    // Unpadded base64 is common in CRS probes — attempt decode
                    // regardless of length%4 (decoder tolerates missing '=');
                    // charset filter already applied by the regex.
                    let mut cands: Vec<&str> = vec![tok];
                    // CRS ships gadget names as base64 variants whose FIRST
                    // sextet is corrupted — one wrong leading char only ruins
                    // decoded byte 0, leaving the gadget name readable from
                    // byte 1 on. Also try dropping a trailing char when the
                    // length is undecodable (len%4==1).
                    if tok.len() % 4 == 1 && tok.len() > 13 {
                        cands.push(&tok[..tok.len() - 1]);
                    }
                    for cand in cands {
                        let Some(bytes) =
                            crate::ast::jwt::JwtTamperingAnalyzer::base64url_decode(cand)
                        else {
                            continue;
                        };
                        let Ok(s) = String::from_utf8(bytes) else {
                            continue;
                        };
                        let sl = s.to_ascii_lowercase();
                        let tail = sl.get(1..).unwrap_or("");
                        let gadget_hit = |g: &&str| {
                            sl.contains(*g)
                                || (g.len() > 4 && !tail.is_empty() && tail.contains(&g[1..]))
                        };
                        let strong = GADGETS.iter().any(gadget_hit);
                        // Dotted class names need only one weak hit; bare
                        // class names (prototypeclonefactory) need two —
                        // single weak words are too common in prose.
                        let weak_hits = WEAK_GADGETS.iter().filter(|g| gadget_hit(*g)).count();
                        let weak = (sl.contains('.') && weak_hits >= 1) || weak_hits >= 2;
                        if strong || weak {
                            tokens.has_java_attack_signal = true;
                            tokens
                                .active_token_names
                                .push("B64_JAVA_GADGET".to_string());
                            break;
                        }
                    }
                    if tokens.has_java_attack_signal {
                        break;
                    }
                }
            }
            // SSRF via IPv6 literals and public-DNS-to-localhost names —
            // checked on parameter VALUES only: bare internal hostnames in
            // Host headers are legitimate for on-prem deployments.
            if !tokens.has_rfi_scheme_signal {
                for cap in RE_PARAM_PAIR_WIDE
                    .get()
                    .unwrap()
                    .captures_iter(&tokens.normalized_text)
                {
                    let vl = cap[2].to_ascii_lowercase();
                    let mut hit = false;
                    for cap6 in RE_IPV6_LITERAL.get().unwrap().captures_iter(&vl) {
                        if Self::is_internal_ipv6(&cap6[1]) {
                            hit = true;
                            break;
                        }
                    }
                    if !hit {
                        hit = RE_LOCALHOST_DNS.get().unwrap().is_match(&vl);
                    }
                    // Multiple @ inside a URL-looking value = userinfo/host
                    // confusion (http://a@b@c). Requires :// so plain emails
                    // and passwords with @ stay benign.
                    if !hit && vl.contains("://") && vl.matches('@').count() >= 2 {
                        hit = true;
                    }
                    if hit {
                        tokens.has_rfi_scheme_signal = true;
                        tokens
                            .active_token_names
                            .push("IPV6_OR_LOCALHOST_SSRF".to_string());
                        break;
                    }
                    // Octal-encoded IPv4 (0251.0376... = 169.254.169.254) and
                    // ANY bracketed IPv6 literal in a URL param are suspicious.
                    if RE_OCTAL_IP.get().unwrap().is_match(&vl)
                        || RE_IPV6_LITERAL.get().unwrap().is_match(&vl)
                    {
                        tokens.has_rfi_scheme_signal = true;
                        tokens
                            .active_token_names
                            .push("ENCODED_IP_SSRF".to_string());
                        break;
                    }
                }
                // Pair-value regexes truncate at ']' — scan the full text for
                // scheme://[ipv6] literals instead (internal OR public: literal
                // IPv6 in request params is vanishingly rare in legit traffic).
                if !tokens.has_rfi_scheme_signal
                    && RE_IPV6_URL.get().unwrap().is_match(&tokens.normalized_text)
                {
                    tokens.has_rfi_scheme_signal = true;
                    tokens
                        .active_token_names
                        .push("IPV6_LITERAL_SSRF".to_string());
                }
            }
            // Nested assignments inside values (month=( / CType='), parameter
            // count floods, U+FFFD from invalid UTF-8, trailing-space values,
            // and multipart filenames carrying parser metacharacters.
            {
                // Count DISTINCT param keys — normalized_text carries raw +
                // decoded variants of the same request, so positional counting
                // inflates by the number of decode passes.
                let mut keys: std::collections::HashSet<&str> = std::collections::HashSet::new();
                for cap in RE_PARAM_PAIR_WIDE
                    .get()
                    .unwrap()
                    .captures_iter(&tokens.normalized_text)
                {
                    keys.insert(cap.get(1).map(|m| m.as_str()).unwrap_or(""));
                    let vl = &cap[2];
                    // CRLF/LF inside a decoded value is only suspicious when it
                    // reconstructs a header (Name:) or splits a new param (k=).
                    let crlf_hit = (vl.contains("\r\n") || vl.contains('\n'))
                        && (RE_CRLF_HEADER.get().unwrap().is_match(vl)
                            || RE_CRLF_PARAM.get().unwrap().is_match(vl));
                    // Lone backslash shorthands (file=\c — value STARTS with
                    // backslash + a letter so C:\ and JSON \" stay benign)
                    // and high-value files.
                    let short_bs = vl.starts_with('\\')
                        && vl.len() >= 2
                        && vl.len() <= 5
                        && vl[1..].chars().all(|c| c.is_ascii_alphabetic());
                    if vl.contains('\u{FFFD}')
                        || RE_NESTED_PARAM.get().unwrap().is_match(vl)
                        || crlf_hit
                        || short_bs
                        || RE_SENSITIVE_FILE.get().unwrap().is_match(vl)
                    {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("VALUE_CANONICALIZATION".to_string());
                        if RE_SENSITIVE_FILE.get().unwrap().is_match(vl) {
                            tokens.has_lfi_extended_signal = true;
                            tokens
                                .active_token_names
                                .push("SENSITIVE_FILE_TARGET".to_string());
                        }
                    }
                    // php.ini-style assignments and template-engine directives
                    // smuggled inside parameter values.
                    if RE_PHP_INI_ASSIGN.get().unwrap().is_match(vl) {
                        tokens.has_php_injection_signal = true;
                        tokens
                            .active_token_names
                            .push("PHP_INI_INJECTION".to_string());
                    }
                    if RE_TEMPLATE_DIR.get().unwrap().is_match(vl) {
                        tokens.has_ssti_expression = true;
                        tokens
                            .active_token_names
                            .push("TEMPLATE_DIRECTIVE".to_string());
                    }
                }
                // HPP: the SAME key repeated >=4 times in the RAW query string.
                // Counted on query_string (not normalized_text) so decode
                // variants cannot inflate the tally; legit multi-value filters
                // rarely exceed 3 repetitions of one key.
                {
                    let mut raw_counts: std::collections::HashMap<&str, usize> =
                        std::collections::HashMap::new();
                    for piece in req.query_string.split(['&', ';']) {
                        if let Some((k, _)) = piece.split_once('=') {
                            *raw_counts.entry(k).or_insert(0) += 1;
                        }
                    }
                    if raw_counts.values().any(|c| *c >= 4) {
                        tokens.has_protocol_enforcement_signal = true;
                        tokens
                            .active_token_names
                            .push("PARAMETER_FANOUT".to_string());
                    }
                }
                if keys.len() >= 24 {
                    tokens.has_protocol_enforcement_signal = true;
                    tokens
                        .active_token_names
                        .push("PARAMETER_FANOUT".to_string());
                }
                if RE_MULTIPART_BAD_FN.get().unwrap().is_match(&req.body) {
                    tokens.has_malicious_upload = true;
                    tokens
                        .active_token_names
                        .push("MULTIPART_FILENAME_ABUSE".to_string());
                }
                // Credentials in the URL query string.
                if RE_CRED_QUERY.get().unwrap().is_match(&req.query_string) {
                    tokens.has_session_token_url_signal = true;
                    tokens
                        .active_token_names
                        .push("CREDENTIAL_IN_URL".to_string());
                }
                // Reflected runtime/framework error strings in bodies.
                if RE_ERROR_REFLECT.get().unwrap().is_match(&norm) {
                    tokens.has_protocol_enforcement_signal = true;
                    tokens
                        .active_token_names
                        .push("ERROR_REFLECTION".to_string());
                }
            }
        }

        tokens.active_token_names.sort();
        tokens.active_token_names.dedup();
        tokens
    }
}
