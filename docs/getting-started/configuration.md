# ⚙️ SATGuardian Edge WAF — Complete Configuration Guide

This guide provides a detailed field-by-field reference and step-by-step instructions for configuring **SATGuardian Edge WAF** via `waf_config.toml` and environment variables.

---

## 📋 Configuration File Location

By default, SATGuardian looks for `waf_config.toml` in the current working directory. You can specify a custom configuration file path using the `--config` flag or the `SATGUARDIAN_CONFIG` environment variable:

```bash
# Using CLI flag
./satguardian-waf proxy --config /etc/satguardian/waf_config.toml

# Using environment variable
export SATGUARDIAN_CONFIG="/etc/satguardian/waf_config.toml"
./satguardian-waf proxy
```

---

## 🌐 1. Network & Core Defense Settings

Configures the inbound proxy listener, the target upstream application backend, and the active defense mode.

```toml
# Inbound HTTP listener address where SATGuardian intercepts incoming web traffic
listen_addr = "0.0.0.0:8080"

# Target upstream backend application (Nginx, Node.js, Python, Go, Java, PHP, IIS, etc.)
upstream_url = "http://127.0.0.1:3000"

# Active perimeter defense mode:
#   "block"   - Active Defense: Instantly drops attacks with HTTP 403 Forbidden.
#   "monitor" - Passive/Dry-Run Mode: Logs attack violations to the ledger but passes traffic upstream.
mode = "block"
```

---

## 🥷 2. Anti-Reconnaissance Protection (Stealth Mode)

Prevents attackers from identifying your security stack through diagnostic response signatures.

```toml
# Enable clean web-standard responses
# true  -> Returns clean HTTP 403 Forbidden without leaking rules, proofs, or server signatures.
# false -> Returns diagnostic JSON payloads containing formal causal proofs (useful for debugging).
stealth_mode = true

# (Optional) Custom HTML or plain text body returned during blocked requests when stealth_mode = true
stealth_block_body = "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1><p>Access Denied by Security Policy</p></center></body></html>"
```

---

## ☁️ 3. Cloud Optimization (Security Units - SU) & SQLite Ledger

Manages asynchronous boolean rule synthesis via **satguardian.tech** and local forensic audit logging.

```toml
# SATGuardian Cloud Optimization API URL for EXACTOR GXOR boolean rule minimization
satguardian_api_url = "https://satguardian.tech/api/simplify"

# Cloud API Key (or configure via SATGUARDIAN_API_KEY environment variable)
satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL Ledger database path for audit logging, anomaly clustering, and digital twin replay
database_path = "waf_ledger.db"

# Autonomous background minimization sync interval in seconds (default: 300s / 5 minutes)
autonomous_sync_interval_secs = 300

# Enable automatic hot-reload minimization sync with satguardian.tech
auto_sync_enabled = true
```

> **Operational Guarantee:** If your monthly Security Units (SU) quota is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud synthesis pauses gracefully while the local Edge WAF continues protecting your application at full speed using its last compiled rule matrix ($0.00 traffic cost).

---

## 🛡️ 4. Layer-7 Behavioral Defense & Rate Limiting

Protects against credential stuffing, brute force login floods, and Layer-7 HTTP DDoS attacks using sliding window ring buffers.

```toml
# Enable stateful temporal ring buffer analysis
stateful_enabled = true

# Maximum total requests permitted per client IP across all endpoints within the sliding window
stateful_global_limit = 300

# Maximum permitted requests per client IP on sensitive authentication routes (/login, /auth, etc.)
stateful_auth_limit = 20

# Temporal sliding window duration in seconds (60s ring buffer)
stateful_window_secs = 60

# Isolation / jail quarantine duration in seconds for offending IPs (180s = 3 minutes)
stateful_ban_secs = 180

# (Optional) Redis URL for distributed multi-node cluster rate limiting
# redis_url = "redis://127.0.0.1:6379"
```

---

## 🔗 5. Envoy Proxy Native Integration (`ext_authz`)

Enables SATGuardian to serve as a sub-millisecond external authorization sidecar for Envoy Proxy and Kubernetes Ingress Controllers.

```toml
# Inbound gRPC/HTTP listener for Envoy's envoy.filters.http.ext_authz filter
envoy_ext_authz_addr = "0.0.0.0:9002"
```

---

## 🏝️ 6. Modular Certainty Islands (`[islands]`)

Enable or disable pre-compiled domain-specific exploit shields.

```toml
[islands]
# WordPress Reconnaissance & Exploit Shield:
# Drops scanner probes targeting /wp-admin, /wp-login.php, xmlrpc.php, and plugin exploits.
# Set to false ONLY if your application legitimately runs WordPress.
wordpress_shield = true

# Sensitive Files & Backdoors Shield:
# Blocks discovery probes targeting /.env, /.git, phpMyAdmin, Spring actuator, and database dumps.
exposure_shield = true

# Modern Framework Exploits Shield:
# Blocks Log4j/JNDI injection, Spring Cloud SpEL, Laravel Ignition, and ThinkPHP RCE probes.
framework_shield = true
```

---

## 🎯 7. Customer Business Access Rules (`[business_rules]`)

Declarative access control policies for specific route prefixes, HTTP methods, IP whitelists, blacklists, and mandatory headers.

```toml
[business_rules]
enabled = true

# Example 1: Enforce Strict HTTP Method Whitelist on API endpoints
[[business_rules.rules]]
id = "biz-api-methods"
name = "Strict API Method Whitelist"
path_prefix = "/api/v1/"
allowed_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
blocked_methods = ["TRACE", "CONNECT", "PATCH"]
allowed_ips = []
blocked_ips = []
required_headers = []
max_body_bytes = 10485760 # 10 MB payload ceiling
enabled = true

# Example 2: IP-Restricted Internal Administrative Gateway
[[business_rules.rules]]
id = "biz-admin-gateway"
name = "Admin Portal IP Restricted Access"
path_prefix = "/internal/admin/"
allowed_methods = ["GET", "POST"]
blocked_methods = []
allowed_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.100"] # Authorized admin IPs
blocked_ips = []
required_headers = ["X-Admin-Token"] # Mandatory administrative header
max_body_bytes = 1048576 # 1 MB body ceiling
enabled = true
```

### Parameter Reference for Business Rules:

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `id` | String | Unique rule identifier. |
| `name` | String | Human-readable description of the rule. |
| `path_prefix` | String | URL path prefix target (e.g. `/api/`, `/admin/`). |
| `allowed_methods` | Array | Allowed HTTP methods (e.g. `["GET", "POST"]`). |
| `blocked_methods` | Array | Blocked HTTP methods (e.g. `["TRACE", "PATCH"]`). |
| `allowed_ips` | Array | Client IP whitelist (if non-empty, unlisted IPs are blocked). |
| `blocked_ips` | Array | Client IP blacklist (listed IPs are instantly dropped). |
| `required_headers` | Array | Mandatory HTTP headers required for request approval. |
| `max_body_bytes` | Integer | Maximum permitted HTTP body size in bytes. |
| `enabled` | Boolean | `true` to activate rule, `false` to disable. |

---

## 🔑 8. Environment Variables Reference

| Variable | Description | Example |
| :--- | :--- | :--- |
| `SATGUARDIAN_CONFIG` | Overrides path to configuration file | `export SATGUARDIAN_CONFIG="/etc/waf_config.toml"` |
| `SATGUARDIAN_API_KEY` | Overrides Cloud Optimization API Key | `export SATGUARDIAN_API_KEY="ek_live_12345"` |
| `RUST_LOG` | Configures logging verbosity | `export RUST_LOG="info"` or `export RUST_LOG="satguardian_waf=debug"` |

---

*© 2026 SATGuardian Cyber-Defense Systems. Sovereign Edge Security Powered by Native Rust & EXACTOR GXOR.*

