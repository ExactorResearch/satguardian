use std::collections::HashMap;

/// Extracted gRPC & Protobuf protocol anomaly tokens.
#[derive(Debug, Clone, Default)]
pub struct GrpcTokens {
    pub is_grpc: bool,
    pub has_grpc_smuggling: bool,
    pub has_grpc_status_injection: bool,
    pub active_tokens: Vec<String>,
}

pub struct GrpcProtobufAnalyzer;

impl GrpcProtobufAnalyzer {
    /// Analyzes headers and body for gRPC framing attacks and status injection smuggling.
    pub fn analyze(headers: &HashMap<String, String>, body: &[u8]) -> GrpcTokens {
        let mut tokens = GrpcTokens::default();

        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        let ct_lower = content_type.to_ascii_lowercase();

        let is_grpc_ct = ct_lower.starts_with("application/grpc");
        if is_grpc_ct {
            tokens.is_grpc = true;
        }

        // 1. Client-Injected gRPC Status / Trailer Injection
        // Attackers inject `grpc-status` or `grpc-message` in request headers to smuggle responses
        // or fool reverse proxy authorization middleware.
        if headers.contains_key("grpc-status")
            || headers.contains_key("grpc-message")
            || headers.contains_key("grpc-status-details-bin")
        {
            tokens.has_grpc_status_injection = true;
            tokens
                .active_tokens
                .push("GRPC_CLIENT_TRAILER_INJECTION_SMUGGLING".to_string());
        }

        // 2. gRPC Protocol Framing Validation
        if is_grpc_ct && !body.is_empty() {
            let body_len = body.len();
            // A valid gRPC frame requires at least 5 bytes:
            // 1 byte: compression flag (0x00 or 0x01)
            // 4 bytes: big-endian length of message
            if body_len < 5 {
                tokens.has_grpc_smuggling = true;
                tokens
                    .active_tokens
                    .push("GRPC_MALFORMED_TRUNCATED_FRAME".to_string());
            } else {
                let compression_flag = body[0];
                if compression_flag > 1 {
                    // Invalid compression flag (only 0 or 1 allowed in gRPC RFC)
                    tokens.has_grpc_smuggling = true;
                    tokens
                        .active_tokens
                        .push("GRPC_INVALID_COMPRESSION_FLAG".to_string());
                }

                let msg_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
                let expected_total_frame = 5 + msg_len;

                // If declared length doesn't match stream length
                if msg_len > 16 * 1024 * 1024 {
                    // Extremely large frame length (> 16MB) in inbound stream -> Memory exhaustion attempt
                    tokens.has_grpc_smuggling = true;
                    tokens
                        .active_tokens
                        .push("GRPC_FRAME_LENGTH_EXHAUSTION".to_string());
                } else if body_len < expected_total_frame {
                    // Truncated body under declared frame size
                    tokens.has_grpc_smuggling = true;
                    tokens
                        .active_tokens
                        .push("GRPC_FRAME_STREAM_DESYNC_SMUGGLING".to_string());
                }
            }
        }

        tokens
    }
}
