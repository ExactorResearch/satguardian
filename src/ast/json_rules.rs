use regex::Regex;
use std::sync::OnceLock;

/// Extracted JSON AST tokens and prototype pollution violation flags.
#[derive(Debug, Clone, Default)]
pub struct JsonTokens {
    pub is_json: bool,
    pub has_proto_pollution: bool,
    pub has_deep_nesting: bool,
    pub max_depth: usize,
    pub active_tokens: Vec<String>,
}

static RE_PROTO_POLLUTION: OnceLock<Regex> = OnceLock::new();
static RE_CONSTRUCTOR_PROTO: OnceLock<Regex> = OnceLock::new();
static RE_UNICODE_PROTO: OnceLock<Regex> = OnceLock::new();

fn init_json_regexes() {
    let _ = RE_PROTO_POLLUTION.get_or_init(|| {
        Regex::new(r#"(?i)"(?:__proto__|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__)"\s*:"#).unwrap()
    });
    let _ = RE_CONSTRUCTOR_PROTO.get_or_init(|| {
        Regex::new(r#"(?i)"constructor"\s*:\s*\{[^}]*"prototype"\s*:"#).unwrap()
    });
    let _ = RE_UNICODE_PROTO.get_or_init(|| {
        Regex::new(r#"(?i)\\u005f\\u005fproto\\u005f\\u005f|\\u002e\\u002e"#).unwrap()
    });
}

pub struct JsonStrictAnalyzer;

impl JsonStrictAnalyzer {
    /// Inspects whether the incoming payload contains JSON or prototype pollution vectors.
    pub fn analyze(body: &str) -> JsonTokens {
        init_json_regexes();
        let mut tokens = JsonTokens::default();

        let trimmed = body.trim();
        let is_json = trimmed.starts_with('{') || trimmed.starts_with('[');
        if is_json {
            tokens.is_json = true;
        }

        // 1. Prototype Pollution keyword checks (JSON, Query string, or form-data)
        if let Some(re) = RE_PROTO_POLLUTION.get() {
            if re.is_match(body) {
                tokens.has_proto_pollution = true;
                tokens.active_tokens.push("JSON_PROTOTYPE_POLLUTION_ATTR".to_string());
            }
        }
        if let Some(re) = RE_CONSTRUCTOR_PROTO.get() {
            if re.is_match(body) {
                tokens.has_proto_pollution = true;
                tokens.active_tokens.push("JSON_CONSTRUCTOR_PROTOTYPE_INJECTION".to_string());
            }
        }
        if let Some(re) = RE_UNICODE_PROTO.get() {
            if re.is_match(body) {
                tokens.has_proto_pollution = true;
                tokens.active_tokens.push("JSON_UNICODE_OBFUSCATED_PROTO_POLLUTION".to_string());
            }
        }

        // Direct substring check as ultra-fast fallback covering query params: __proto__[ or __proto__. or __proto__=
        if !tokens.has_proto_pollution {
            let body_lower = body.to_ascii_lowercase();
            if body_lower.contains("__proto__")
                || (body_lower.contains("constructor") && body_lower.contains("prototype"))
            {
                tokens.has_proto_pollution = true;
                tokens.active_tokens.push("JSON_PROTOTYPE_POLLUTION_ATTR".to_string());
            }
        }

        // 2. Strict Schema Depth / Nesting Exhaustion Bomb (depth > 20) only if JSON structure
        if is_json {
            let max_depth = Self::calculate_json_depth(trimmed);
            tokens.max_depth = max_depth;
            if max_depth > 20 {
                tokens.has_deep_nesting = true;
                tokens.active_tokens.push("JSON_RECURSIVE_SCHEMA_EXHAUSTION_BOMB".to_string());
            }
        }

        tokens
    }

    /// Accurately counts JSON nesting depth across `{` and `[`, ignoring string contents.
    fn calculate_json_depth(json_str: &str) -> usize {
        let mut max_depth = 0usize;
        let mut current_depth = 0usize;
        let mut in_string = false;
        let mut escape_next = false;

        for ch in json_str.chars() {
            if in_string {
                if escape_next {
                    escape_next = false;
                } else if ch == '\\' {
                    escape_next = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }

            match ch {
                '"' => in_string = true,
                '{' | '[' => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                }
                '}' | ']' => {
                    if current_depth > 0 {
                        current_depth -= 1;
                    }
                }
                _ => {}
            }
        }

        max_depth
    }
}
