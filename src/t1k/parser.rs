//! Parses raw T1K request chunks into normalized HttpRequestPayload for the SATGuardian SAT solver.

use crate::types::HttpRequestPayload;
use std::collections::HashMap;

/// Metadata extracted from the T1K TAG_EXTRA packet.
#[derive(Debug, Clone, Default)]
pub struct T1kExtraMetadata {
    pub uuid: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub local_addr: Option<String>,
    pub local_port: Option<u16>,
    pub scheme: Option<String>,
    pub server_name: Option<String>,
    pub proxy_name: Option<String>,
}

impl T1kExtraMetadata {
    pub fn parse(extra_bytes: &[u8]) -> Self {
        let mut meta = Self::default();
        let text = String::from_utf8_lossy(extra_bytes);

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim();
                let val = v.trim();
                match key {
                    "UUID" => meta.uuid = Some(val.to_string()),
                    "RemoteAddr" => meta.remote_addr = Some(val.to_string()),
                    "RemotePort" => meta.remote_port = val.parse().ok(),
                    "LocalAddr" => meta.local_addr = Some(val.to_string()),
                    "LocalPort" => meta.local_port = val.parse().ok(),
                    "Scheme" => meta.scheme = Some(val.to_string()),
                    "ServerName" => meta.server_name = Some(val.to_string()),
                    "ProxyName" => meta.proxy_name = Some(val.to_string()),
                    _ => {}
                }
            }
        }

        meta
    }
}

/// Parses the T1K raw header chunk, optional body, and extra metadata into HttpRequestPayload.
pub fn parse_t1k_request(
    header_bytes: &[u8],
    body_bytes: Option<&[u8]>,
    extra_bytes: Option<&[u8]>,
) -> (HttpRequestPayload, T1kExtraMetadata) {
    let header_str = String::from_utf8_lossy(header_bytes);
    let extra_meta = extra_bytes
        .map(T1kExtraMetadata::parse)
        .unwrap_or_default();

    let mut lines = header_str.lines();

    let mut method = "GET".to_string();
    let mut raw_uri = "/".to_string();

    // 1. Parse Request-Line (e.g., "GET /api/v1?id=1 HTTP/1.1")
    if let Some(first_line) = lines.next() {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if !parts.is_empty() {
            method = parts[0].to_uppercase();
        }
        if parts.len() > 1 {
            raw_uri = parts[1].to_string();
        }
    }

    // 2. Parse URI into path and query_string
    let (path, query_string) = match raw_uri.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_uri, String::new()),
    };

    // 3. Parse Headers
    let mut headers = HashMap::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    // 4. Parse Body
    let body = body_bytes
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();

    // 5. Construct Payload
    let mut payload = HttpRequestPayload::new(method, path, query_string, body);
    payload.headers = headers;
    payload.client_ip = extra_meta.remote_addr.clone();

    if let Some(ref custom_id) = extra_meta.uuid {
        payload.id = custom_id.clone();
    }

    (payload, extra_meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_t1k_request() {
        let raw_header = b"POST /search?q=1%27%20OR%201=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n";
        let raw_body = b"{\"user\":\"admin\"}";
        let raw_extra = b"UUID: event-123456\nRemoteAddr: 10.0.1.20\nRemotePort: 49152\n";

        let (payload, meta) = parse_t1k_request(raw_header, Some(raw_body), Some(raw_extra));

        assert_eq!(payload.method, "POST");
        assert_eq!(payload.path, "/search");
        assert_eq!(payload.query_string, "q=1%27%20OR%201=1");
        assert_eq!(payload.body, "{\"user\":\"admin\"}");
        assert_eq!(payload.id, "event-123456");
        assert_eq!(payload.client_ip, Some("10.0.1.20".to_string()));
        assert_eq!(meta.remote_port, Some(49152));
        assert_eq!(payload.headers.get("host").map(String::as_str), Some("example.com"));
    }
}
