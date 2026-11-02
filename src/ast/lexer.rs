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
        Regex::new(r#"(?i)\bunion(?:\s+|/\*.*?\*/|[(])+(?:all(?:\s+|/\*.*?\*/|[(])+)?select\b"#).unwrap()
    });
    let _ = RE_SQL_SLEEP.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\("#).unwrap()
    });
    let _ = RE_STACKED_DDL.get_or_init(|| {
        Regex::new(r#"(?i)(?:;|\bunion\b).*?\b(?:drop\s+table|truncate\s+table|alter\s+table|insert\s+into|delete\s+from)\b"#).unwrap()
    });
    let _ = RE_XSS_SCRIPT.get_or_init(|| {
        // The leading `<` alternative was removed: it turned every closing </script>
        // into an XSS match and blocked legitimate script includes.
        Regex::new(r#"(?is)<\s*script[^>]*>.*?(?:alert|eval|document|window|fetch|prompt|location)"#).unwrap()
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
        Regex::new(r#"(?i)(?:javascript|vbscript):[^\s'"]+|data:(?:text/html|application/xhtml\+xml|image/svg\+xml|text/javascript)[^\s'"]*"#).unwrap()
    });
    let _ = RE_XSS_SVG.get_or_init(|| {
        Regex::new(r#"(?i)<\s*svg[\s/]+onload\s*="#).unwrap()
    });
    let _ = RE_SHELL_CHAIN.get_or_init(|| {
        // `${IFS}` is a whitespace substitute used to bypass naive shell filters.
        Regex::new(r#"(?i)(?:;|\|\||\||&&|[\r\n]+|`|\$\([^)]+\))(?:\s|\$\{?IFS\}?)*(?:cat|bash|curl|wget|nc|whoami|id|sh|powershell|cmd\.exe|type|ls|netstat|uname|python[0-9.]*|perl|php|ruby|node)\b"#).unwrap()
    });
    let _ = RE_BASE64_DECODE.get_or_init(|| {
        // `base64` alone is common in data URIs; only flag the decoder invocation.
        Regex::new(r#"(?i)(?:;|&&|\|\||\||[\r\n])\s*base64\s+(?:-d|--decode|-D)\b"#).unwrap()
    });
    let _ = RE_POWERSHELL_EXEC.get_or_init(|| {
        Regex::new(r#"(?i)\b(?:powershell(?:\.exe)?|pwsh)\s+(?:-(?:nop|noprofile|enc|encodedcommand|command|executionpolicy|w|windowstyle)\b|/(?:c|k)\b)|\bcmd(?:\.exe)?\s+/c\b"#).unwrap()
    });
    let _ = RE_SUBSHELL.get_or_init(|| {
        Regex::new(r#"(?i)(?:`[^`]+`|\$\([^)]+\))"#).unwrap()
    });
    let _ = RE_DYNAMIC_EVAL.get_or_init(|| {
        // No trailing \b: alternatives ending in `(` are followed by a non-word char.
        Regex::new(r#"(?i)\b(?:os\.system|subprocess\.|eval\(|exec\(|runtime\.getruntime\(\)\.exec|getruntime\(\)\.exec|new\s+processbuilder|processbuilder\s*\(|passthru\(|shell_exec\()"#).unwrap()
    });
    let _ = RE_PATH_TRAVERSAL.get_or_init(|| {
        // Accept backslash targets and collapsed dots (`....//`) used to evade filters.
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|%252e%252e%252f|(?:\.{2,}[/\\])+)(?:.*?(?:etc/passwd|etc/shadow|boot\.ini|windows[/\\]win\.ini|proc/self|winnt[/\\]win\.ini))"#).unwrap()
    });
    let _ = RE_PATH_DIRECT_SYSTEM.get_or_init(|| {
        Regex::new(r#"(?i)(?:/proc/self/(?:environ|cmdline|maps)|/etc/passwd|/etc/shadow|/windows/win\.ini|c:[/\\]boot\.ini)"#).unwrap()
    });
    let _ = RE_PATH_DOTS_ONLY.get_or_init(|| {
        Regex::new(r#"(?i)(?:\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|(?:\.{2,}[/\\])+){2,}"#).unwrap()
    });
    let _ = RE_SSRF_CLOUD.get_or_init(|| {
        Regex::new(r#"(?i)(?:https?|gopher|dict|file)://(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|instance-data|\[fd00:ec2::254\]|2852039166)(?::\d+)?(?:/|$|\?)"#).unwrap()
    });
    let _ = RE_SSRF_PRIVATE.get_or_init(|| {
        Regex::new(r#"(?i)(?:https?|gopher|dict|file)://(?:127\.\d{1,3}(?:\.\d{1,3}){0,2}|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|\[::1\]|\[::ffff:127\.0\.0\.1\]|\[::ffff:7f00:1\]|\[::ffff:169\.254\.169\.254\]|\[::ffff:a9fe:a9fe\]|2130706433|0x7f000001)(?::\d+)?(?:/|$|\?)"#).unwrap()
    });
    let _ = RE_SSRF_PARAM_CONTEXT.get_or_init(|| {
        Regex::new(r#"(?i)(?:^|[^a-z0-9_])(?:url|uri|host|hostname|redirect|redirect_uri|redirecturl|return|returnurl|next|continue|callback|callbackurl|webhook|webhookurl|target|targeturl|dest|destination|proxy|fetch|src|source|image|img|file|path|domain|endpoint|check|connect)\s*['"]?\s*[=:]\s*['"]?$"#).unwrap()
    });
    let _ = RE_COMMENT_STRIP.get_or_init(|| {
        Regex::new(r#"/\*.*?\*/"#).unwrap()
    });
    let _ = RE_WORDPRESS_PROBE.get_or_init(|| {
        // Generic index.php/wp.php are NOT WordPress-specific and used to flag ThinkPHP probes
        // as CMS reconnaissance. Keep only unambiguous WordPress paths.
        Regex::new(r#"(?i)(?:/wp-(?:admin|login\.php|includes|content|cron\.php|config\.php|json)|xmlrpc\.php|\?author=\d+|wlwmanifest\.xml)"#).unwrap()
    });
    let _ = RE_SENSITIVE_EXPOSURE.get_or_init(|| {
        Regex::new(r#"(?i)(?:/\.env(?:\.[a-z0-9_-]+)?|/\.git(?:/|$|\?)|/\.aws/credentials|/(?:phpmyadmin|pma|adminer\.php|actuator(?:/[a-z]+)?|swagger-ui|\.svn|docker-compose\.ya?ml|Dockerfile|dump\.sql|backup\.sql|web\.config))"#).unwrap()
    });
    let _ = RE_FRAMEWORK_EXPLOIT.get_or_init(|| {
        Regex::new(r#"(?i)(?:\$\{jndi:(?:ldap|rmi|dns|corba|iiop)|#\{T\([a-z0-9_.]+\)|\$\{T\([a-z0-9_.]+\)|_ignition/execute-solution|invokefunction&function=call_user_func)"#).unwrap()
    });
    let _ = RE_MYSQL_EXEC_COMMENT.get_or_init(|| {
        // /*!50000UNION*/ is executed by MySQL, so its content must be inspected, not stripped.
        Regex::new(r#"/\*![0-9]*\s*([\s\S]*?)\*/"#).unwrap()
    });
    let _ = RE_JNDI_OBFUSCATION.get_or_init(|| {
        Regex::new(r#"(?i)\$\{(lower|upper):([^}]*)\}"#).unwrap()
    });
    let _ = RE_JNDI_ENV_LOOKUP.get_or_init(|| {
        Regex::new(r#"(?i)\$\{env:[^}]*:-([^}]*)\}"#).unwrap()
    });
    let _ = RE_TAUT_NUMERIC.get_or_init(|| {
        Regex::new(r#"(?i)(?:or|and|\|\|)\s*\(?\s*(\d{1,10})\s*(>=|<=|>|<|!=)\s*(\d{1,10})\s*\)?"#).unwrap()
    });
    let _ = RE_OR_NUMERIC_COMMENT.get_or_init(|| {
        Regex::new(r#"(?i)['"]?\s*(?:or|and|\|\|)\s+\d{1,10}\s*(?:--|#|/\*)"#).unwrap()
    });
    let _ = RE_OVERLONG_DOT.get_or_init(|| {
        Regex::new(r#"(?i)%(?:c0|c1)%(?:ae|2e)|%e0%80%ae|%f0%80%80%ae"#).unwrap()
    });
    let _ = RE_OVERLONG_SLASH.get_or_init(|| {
        Regex::new(r#"(?i)%(?:c0|c1)%(?:af|2f|bc)|%e0%80%af|%f0%80%80%af"#).unwrap()
    });
    let _ = RE_OVERLONG_BACKSLASH.get_or_init(|| {
        Regex::new(r#"(?i)%(?:c0|c1)%(?:5c|9c|dc)|%e0%80%9c|%f0%80%80%9c"#).unwrap()
    });
    let _ = RE_IIS_DOT.get_or_init(|| {
        Regex::new(r#"(?i)%uff0e|%u002e"#).unwrap()
    });
    let _ = RE_IIS_SLASH.get_or_init(|| {
        Regex::new(r#"(?i)%u2215|%u002f|%uff0f"#).unwrap()
    });
    let _ = RE_IIS_BACKSLASH.get_or_init(|| {
        Regex::new(r#"(?i)%u2216|%u005c|%uff3c"#).unwrap()
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

        // Pass 0: Overlong UTF-8 / IIS encodings decode to replacement chars if left to the
        // UTF-8 decoder, so rewrite them into `.`, `/`, `\` before percent decoding.
        let raw_path = Self::decode_overlong_encodings(raw);
        if raw_path != raw {
            is_obfuscated = true;
        }

        // Pass 1: Decode
        let d1 = percent_decode_str(&raw_path).decode_utf8_lossy().to_string();
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
                '\0' => {
                    is_obfuscated = true;
                    d4.push(' ');
                }
                _ => d4.push(c),
            }
        }

        // Pass 5: Decode JSON/Unicode/Hex escapes (\uXXXX and \xXX) in any case, including dots, quotes, slashes, brackets
        let mut d5 = d4.clone();
        if d5.contains("\\u") || d5.contains("\\U") || d5.contains("\\x") || d5.contains("\\X") {
            let mut decoded = String::with_capacity(d5.len());
            let chars: Vec<char> = d5.chars().collect();
            let mut i = 0;
            while i < chars.len() {
                if i + 5 < chars.len() && chars[i] == '\\' && (chars[i + 1] == 'u' || chars[i + 1] == 'U') {
                    let hex_str: String = chars[i + 2..=i + 5].iter().collect();
                    if let Ok(code) = u32::from_str_radix(&hex_str, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            decoded.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                } else if i + 3 < chars.len() && chars[i] == '\\' && (chars[i + 1] == 'x' || chars[i + 1] == 'X') {
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
        ] {
            if !parts.contains(&variant) {
                parts.push(variant);
            }
        }
        (parts.join(" "), is_obfuscated)
    }

    fn decode_overlong_encodings(raw: &str) -> String {
        if !raw.contains('%') {
            return raw.to_string();
        }
        let mut decoded = RE_OVERLONG_DOT.get().unwrap().replace_all(raw, ".").to_string();
        decoded = RE_OVERLONG_SLASH.get().unwrap().replace_all(&decoded, "/").to_string();
        decoded = RE_OVERLONG_BACKSLASH.get().unwrap().replace_all(&decoded, "\\").to_string();
        decoded = RE_IIS_DOT.get().unwrap().replace_all(&decoded, ".").to_string();
        decoded = RE_IIS_SLASH.get().unwrap().replace_all(&decoded, "/").to_string();
        RE_IIS_BACKSLASH.get().unwrap().replace_all(&decoded, "\\").to_string()
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
                    let decoded = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
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
        if !text.bytes().any(|b| b == b'\t' || b == b'\n' || b == b'\r' || b == 0) {
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
        if !lower.contains("${lower:") && !lower.contains("${upper:") && !lower.contains("${env:") {
            return text.to_string();
        }
        let casing = RE_JNDI_OBFUSCATION.get().unwrap();
        let env = RE_JNDI_ENV_LOOKUP.get().unwrap();
        let mut current = text.to_string();
        for _ in 0..4 {
            let next = casing
                .replace_all(&current, |caps: &regex::Captures| {
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
                        tokens.active_token_names.push("TAUTOLOGY_NUMERIC".to_string());
                        break;
                    }
                }
            }
        }
        if !tokens.has_tautology && RE_OR_NUMERIC_COMMENT.get().unwrap().is_match(&normalized) {
            tokens.has_tautology = true;
            tokens.active_token_names.push("TAUTOLOGY_NUMERIC_COMMENT".to_string());
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
        if RE_XSS_SCRIPT.get().unwrap().is_match(&normalized) {
            tokens.has_script_tag = true;
            tokens.active_token_names.push("SCRIPT_ELEMENT".to_string());
        }
        if RE_XSS_REMOTE_SCRIPT.get().unwrap().is_match(&normalized) {
            tokens.has_script_tag = true;
            tokens.active_token_names.push("REMOTE_SCRIPT_INCLUDE".to_string());
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
        if RE_DYNAMIC_EVAL.get().unwrap().is_match(&normalized)
            || RE_POWERSHELL_EXEC.get().unwrap().is_match(&normalized)
        {
            tokens.has_dynamic_eval = true;
            tokens.active_token_names.push("DYNAMIC_CODE_RUNTIME".to_string());
        }
        if RE_BASE64_DECODE.get().unwrap().is_match(&normalized) {
            tokens.has_shell_chain = true;
            tokens.active_token_names.push("BASE64_DECODE_EXECUTION".to_string());
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

        // 5. SSRF Tokens. Cloud metadata is always a violation. Loopback/RFC1918
        // targets are only violations when they appear in a URL-like parameter,
        // otherwise documentation and issue text trigger false positives.
        if RE_SSRF_CLOUD.get().unwrap().is_match(&normalized) {
            tokens.has_ssrf_metadata = true;
            tokens.active_token_names.push("CLOUD_METADATA_ENDPOINT".to_string());
        } else if RE_SSRF_PRIVATE.get().unwrap().is_match(&normalized)
            && Self::has_ssrf_param_context(&normalized)
        {
            tokens.has_ssrf_metadata = true;
            tokens.active_token_names.push("PRIVATE_NETWORK_ENDPOINT".to_string());
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
