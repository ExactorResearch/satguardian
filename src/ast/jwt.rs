use crate::ast::lexer::AstLexer;
use std::collections::HashMap;

/// Extracted JWT tokens and tampering violation flags.
#[derive(Debug, Clone, Default)]
pub struct JwtTokens {
    pub is_jwt: bool,
    pub has_alg_none: bool,
    pub has_missing_signature: bool,
    pub has_header_injection: bool,
    pub active_tokens: Vec<String>,
}

pub struct JwtTamperingAnalyzer;

impl JwtTamperingAnalyzer {
    /// Inspects headers, cookies, and text to detect JWT tampering, `alg: none`, and header injection.
    pub fn analyze(headers: &HashMap<String, String>, full_text: &str) -> JwtTokens {
        let mut tokens = JwtTokens::default();

        // 1. Look for JWT in Authorization header or other standard headers
        let mut potential_tokens = Vec::new();
        for (k, v) in headers {
            let kl = k.to_ascii_lowercase();
            if kl == "authorization" {
                if let Some(bearer) = v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")) {
                    potential_tokens.push(bearer.trim());
                } else {
                    potential_tokens.push(v.trim());
                }
            } else if kl == "cookie" || kl.contains("token") || kl.contains("jwt") || kl.contains("auth") {
                // Check if cookie or header contains eyJ...
                for part in v.split([';', ' ', ',']) {
                    let p = part.trim();
                    if let Some(val) = p.split('=').nth(1) {
                        if val.starts_with("eyJ") {
                            potential_tokens.push(val.trim());
                        }
                    } else if p.starts_with("eyJ") {
                        potential_tokens.push(p);
                    }
                }
            }
        }

        // Also check full_text for raw tokens starting with eyJ
        if potential_tokens.is_empty() {
            for word in full_text.split_whitespace() {
                let w = word.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == ';');
                if w.starts_with("eyJ") && w.contains('.') {
                    potential_tokens.push(w);
                }
            }
        }

        for token_candidate in potential_tokens {
            Self::inspect_single_jwt(token_candidate, &mut tokens);
        }

        tokens
    }

    fn inspect_single_jwt(raw_jwt: &str, tokens: &mut JwtTokens) {
        let parts: Vec<&str> = raw_jwt.split('.').collect();
        let parts_len = parts.len();
        // A JWT must have at least 2 parts (header.payload) or 3 parts (header.payload.signature)
        if parts_len < 2 {
            return;
        }

        let header_b64 = parts[0];
        let _payload_b64 = parts[1];
        let sig_part = if parts_len >= 3 { parts[2] } else { "" };

        // Attempt Base64URL decode of header
        if let Some(header_bytes) = Self::base64url_decode(header_b64) {
            if let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&header_bytes) {
                tokens.is_jwt = true;

                // 1. Check Algorithm Confusion / `alg: "none"`
                let alg_val = header_json.get("alg");
                match alg_val.and_then(|a| a.as_str()) {
                    Some(alg) => {
                        let trimmed_alg = alg.trim();
                        if trimmed_alg.is_empty() || trimmed_alg.eq_ignore_ascii_case("none") {
                            tokens.has_alg_none = true;
                            tokens.active_tokens.push("JWT_ALG_NONE_VULNERABILITY".to_string());
                        }
                    }
                    None if alg_val.is_none() => {
                        // Missing alg attribute
                        tokens.has_alg_none = true;
                        tokens.active_tokens.push("JWT_MISSING_ALG_FIELD".to_string());
                    }
                    _ => {}
                }

                // 2. Check Missing Signature
                if sig_part.trim().is_empty() {
                    tokens.has_missing_signature = true;
                    tokens.active_tokens.push("JWT_MISSING_SIGNATURE_PART".to_string());
                }

                // 3. Check Header Parameter Injection: jku, jwk, x5u, kid
                if header_json.get("jwk").is_some() {
                    tokens.has_header_injection = true;
                    tokens.active_tokens.push("JWT_EMBEDDED_JWK_KEY_SPOOFING".to_string());
                }
                if let Some(jku) = header_json.get("jku").and_then(|j| j.as_str()) {
                    // Remote JWK URL probe / SSRF
                    if jku.contains("169.254") || jku.contains("localhost") || jku.contains("http://") {
                        tokens.has_header_injection = true;
                        tokens.active_tokens.push("JWT_JKU_REMOTE_KEY_SSRF".to_string());
                    }
                }
                if let Some(kid) = header_json.get("kid").and_then(|k| k.as_str()) {
                    // Check for Directory Traversal or SQLi in kid (normalized)
                    let (kid_norm, _) = AstLexer::normalize_string(kid);
                    let kid_lower = kid_norm.to_ascii_lowercase();
                    if kid_lower.contains("../") || kid_lower.contains("..\\") || kid_lower.contains("/dev/null") {
                        tokens.has_header_injection = true;
                        tokens.active_tokens.push("JWT_KID_PATH_TRAVERSAL_INJECTION".to_string());
                    } else if kid_lower.contains("union") || kid_norm.contains('\'') || kid_norm.contains('"') || kid_norm.contains('|') || kid_lower.contains("waitfor") {
                        tokens.has_header_injection = true;
                        tokens.active_tokens.push("JWT_KID_SQLI_COMMAND_INJECTION".to_string());
                    }
                }
            }
        }
    }

    /// Fast zero-dependency Base64URL decoder supporting both URL-safe (`-`, `_`) and standard base64 (`+`, `/`).
    pub fn base64url_decode(input: &str) -> Option<Vec<u8>> {
        let mut clean = input.replace('-', "+").replace('_', "/");
        // Pad with '=' to a multiple of 4
        while clean.len() % 4 != 0 {
            clean.push('=');
        }

        let bytes = clean.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

        fn decode_char(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }

        let mut i = 0;
        while i < bytes.len() {
            let b0 = decode_char(bytes[i])?;
            let b1 = decode_char(bytes[i + 1])?;
            let b2 = if bytes[i + 2] == b'=' { None } else { Some(decode_char(bytes[i + 2])?) };
            let b3 = if bytes[i + 3] == b'=' { None } else { Some(decode_char(bytes[i + 3])?) };

            out.push((b0 << 2) | (b1 >> 4));
            if let Some(c2) = b2 {
                out.push(((b1 & 0x0F) << 4) | (c2 >> 2));
                if let Some(c3) = b3 {
                    out.push(((c2 & 0x03) << 6) | c3);
                }
            }
            i += 4;
        }

        Some(out)
    }
}
