//! Client IP resolution with an explicit trusted-proxy allowlist.
//! Forwarding headers are only honored when the TCP peer is a trusted proxy.

use axum::http::HeaderMap;
use std::net::IpAddr;

#[derive(Debug, Clone)]
enum Cidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl Cidr {
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (ip_str, prefix_str) = match raw.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (raw, None),
        };
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| format!("invalid trusted proxy IP/CIDR '{}'", raw))?;

        match ip {
            IpAddr::V4(v4) => {
                let prefix = match prefix_str {
                    Some(p) => p
                        .parse::<u8>()
                        .map_err(|_| format!("invalid IPv4 prefix in '{}'", raw))?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(format!("IPv4 prefix out of range in '{}'", raw));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Cidr::V4 {
                    network: u32::from(v4) & mask,
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                let prefix = match prefix_str {
                    Some(p) => p
                        .parse::<u8>()
                        .map_err(|_| format!("invalid IPv6 prefix in '{}'", raw))?,
                    None => 128,
                };
                if prefix > 128 {
                    return Err(format!("IPv6 prefix out of range in '{}'", raw));
                }
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Cidr::V6 {
                    network: u128::from(v6) & mask,
                    prefix,
                })
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(v4)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - *prefix)
                };
                (u32::from(v4) & mask) == *network
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(v6)) => {
                let mask = if *prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - *prefix)
                };
                (u128::from(v6) & mask) == *network
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustedProxies {
    nets: Vec<Cidr>,
}

impl TrustedProxies {
    /// Parses exact IPs and CIDR ranges. Loopback is always trusted so a local
    /// Envoy sidecar or reverse proxy can supply forwarding headers.
    pub fn parse(entries: &[String]) -> Result<Self, String> {
        let mut nets = vec![Cidr::parse("127.0.0.0/8")?, Cidr::parse("::1/128")?];
        for raw in entries {
            if raw.trim().is_empty() {
                continue;
            }
            nets.push(Cidr::parse(raw)?);
        }
        Ok(Self { nets })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }
}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self::parse(&[]).expect("loopback CIDRs are valid")
    }
}

/// Returns the effective client IP. Untrusted peers can never spoof it through
/// `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` or `True-Client-IP`.
pub fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &TrustedProxies) -> String {
    if !trusted.contains(peer) {
        return peer.to_string();
    }

    // Walk the chain right-to-left, skipping trusted proxies. The first
    // untrusted hop is the client observed by the nearest trusted proxy.
    for value in headers.get_all("x-forwarded-for").iter() {
        if let Ok(raw) = value.to_str() {
            for candidate in raw.split(',').rev() {
                if let Ok(ip) = candidate.trim().parse::<IpAddr>() {
                    if !trusted.contains(ip) {
                        return ip.to_string();
                    }
                }
            }
        }
    }

    for name in ["cf-connecting-ip", "true-client-ip", "x-real-ip"] {
        if let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = value.trim().parse::<IpAddr>() {
                if !trusted.contains(ip) {
                    return ip.to_string();
                }
            }
        }
    }

    peer.to_string()
}
