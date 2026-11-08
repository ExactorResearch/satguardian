# ⚙️ SATGuardian Edge WAF — Configuration Reference

> **Status: research prototype, not a production-ready WAF.** Detection has one held-out
> estimate (`benchmarks/real_comparative/corpus/heldout_v10.jsonl`,
> **38.6% recall on 70 attacks**, 95% CI 28.0–50.3%, and **0.0% false positives on 44
> controls**, 95% CI 0.0–8.0%, run once 2026-11-08, same-author payloads, no
> third-party evaluation) — the current engine measures 100%/0.0% on the same
> batch as a post-tuning diagnostic; the earlier `heldout_v2` figure (56.1%/7.0%)
> remains for provenance. The in-sample 100% / 0%
> rows in `corpus/independent_v1.json` are regression floors, not generalization estimates.
> See [Project Status](../status.md) and the [Detection Corpus](../corpus.md).

This guide provides a field-by-field reference for configuring **SATGuardian Edge WAF** via
`waf_config.toml` and environment variables.

**The control rule in one line:** free, you get local protection on your own node; paying,
you get continuous review of new patterns, update proposals and explanations — without ever
giving up control of your WAF. Every cloud result below is a proposal until you approve it.

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

# Defense mode:
#   "block"   - Detected requests are rejected with HTTP 403 Forbidden.
#   "monitor" - Dry-run mode: violations are logged to the ledger, traffic passes upstream.
mode = "block"
```

`upstream_url` must start with `http://` or `https://` — the client refuses to start
otherwise. The listener itself is plain HTTP: this build does not terminate TLS and does
not proxy WebSocket upgrades, so TLS belongs to an nginx/Envoy hop in front of it.

---

## 🥷 2. Anti-Reconnaissance Protection (Stealth Mode)

Prevents attackers from identifying your security stack through diagnostic response signatures.

```toml
# Enable clean web-standard responses
# true  -> Returns a generic HTTP 403 Forbidden without leaking rules, proofs, or server signatures.
# false -> Returns diagnostic JSON containing the causal trace (useful for debugging).
stealth_mode = true

# (Optional) Custom HTML or plain text body returned for blocked requests when stealth_mode = true
stealth_block_body = "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1><p>Access Denied by Security Policy</p></center></body></html>"
```

Per launch you can override the file: `satguardian-waf proxy --verbose` emits the
diagnostic JSON, `satguardian-waf proxy --stealth` forces the generic block response.

---

## 🎛️ 3. Management API & Request Limits

The management API is what you use to look at and approve cloud proposals. It never runs
on the public data-plane port.

```toml
# Dedicated listener for /api/waf/*. Set to "off" to disable the management API entirely.
admin_listen_addr = "127.0.0.1:10001"

# Bearer token required by every management route. Prefer the SATGUARDIAN_ADMIN_TOKEN
# environment variable over storing it in the file.
# admin_token = "change-me"

# Maximum accepted inbound request body (2 MiB).
max_body_bytes = 2097152

# Exact IPs or CIDR ranges of upstream proxies allowed to supply X-Forwarded-For /
# X-Real-IP / CF-Connecting-IP / True-Client-IP. Loopback is always trusted.
trusted_proxies = []
```

| Route | Purpose |
| :--- | :--- |
| `GET /health`, `GET /livez` | Liveness; the only routes that are not token-protected. |
| `POST /api/waf/inspect` | Evaluate one request payload and print the causal trace. |
| `GET /api/waf/metrics`, `/api/waf/rules`, `/api/waf/islands` | Read engine state. |
| `GET`/`POST /api/waf/islands/config` | Read or change the islands switches. |
| `GET`/`POST /api/waf/rules/customer`, `DELETE /api/waf/rules/customer/{id}` | Manage declarative business rules. |
| `POST /api/waf/sync-simplify` | One opt-in cloud review batch; the result is stored as proposals. |
| `GET /api/waf/clauses/pending` | List proposals waiting for a decision. |
| `POST /api/waf/clauses/{id}/apply` | **The approval step** — register the clause in the running engine. |
| `DELETE /api/waf/clauses/{id}` | Discard a proposal. Never removes a clause already enforcing. |

With no admin token configured these routes answer `503 management_api_disabled`. The
listener is plain HTTP on loopback by default — if you expose it anywhere, put a
TLS-terminating authenticated proxy in front.

---

## ☁️ 4. Cloud Review (Security Units - SU) & SQLite Ledger

Optional contact with **satguardian.tech** for Boolean rule synthesis, plus local forensic
audit logging.

Boolean minimization is **server-side only**. This client normalizes a request into a
128-bit `FeatureVector` (`u128`), evaluates compiled clauses locally, and — only when you
opt in — sends recorded minterms to the cloud endpoint and stores what comes back as
proposals. No minimizer ships in the client binary or lives in this repository.

```toml
# SATGuardian cloud endpoint for Boolean rule synthesis
satguardian_api_url = "https://satguardian.tech/api/simplify"

# Cloud API Key (or configure via SATGUARDIAN_API_KEY environment variable)
satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL Ledger database path: audit log, anomaly clustering and update proposals
database_path = "waf_ledger.db"

# Seconds between background cloud review runs. Only used when auto_sync_enabled is on.
autonomous_sync_interval_secs = 300

# Opt-in switch. False by default: nothing leaves the node unless you turn this on.
auto_sync_enabled = false
```

**What `auto_sync_enabled = true` does and does not do.** It only uploads the `u128`
feature vectors recorded as novel anomalies (patterns awaiting analysis) on that timer —
not raw traffic, headers, bodies or client IPs. Results are stored with
`dynamic_clauses.applied = 0`: they do not enter the running engine and are not loaded at
startup. Making one enforce is a separate action you take:

```bash
./satguardian-waf clauses list
./satguardian-waf clauses apply <id>
./satguardian-waf clauses reject <id>
```

Review on demand instead of on a timer with `./satguardian-waf sync-simplify --limit 100`
or `POST /api/waf/sync-simplify`.

> **Quota behavior:** cloud synthesis is metered in Security Units (SU) per job and the
> balance is readable with `satguardian-waf entitlement`. A failed review call — including
> one rejected for an exhausted SU balance — is logged and simply produces no proposals;
> the Edge WAF keeps enforcing the last rule matrix you approved. The client treats every
> non-2xx answer as a generic cloud error today; there is no dedicated `402
> SU_QUOTA_EXHAUSTED` branch in this build. Local inspection is never metered.

---

## 🛡️ 5. Layer-7 Behavioral Defense & Rate Limiting

Protects against credential stuffing, brute force login floods, and Layer-7 HTTP floods
using sliding window ring buffers.

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

## 🔗 6. Envoy Proxy Native Integration (`ext_authz`)

Runs SATGuardian as an external authorization service for the `envoy.filters.http.ext_authz`
filter.

```toml
# Inbound HTTP listener for Envoy's envoy.filters.http.ext_authz filter
envoy_ext_authz_addr = "0.0.0.0:9002"
```

This is the HTTP form of `ext_authz`: the service reads `x-envoy-original-method` and
`x-envoy-original-path` and answers the check itself. The gRPC `ext_authz` protocol is not
implemented in this build, and a Unix socket alternative is available via
`satguardian-waf envoy-authz --socket /var/run/waf.sock`.

The check itself costs tens of microseconds in memory; the end-to-end latency your clients
see still includes TLS, Envoy and your upstream, which this project does not measure.

---

## 🏝️ 7. Modular Certainty Islands (`[islands]`)

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

## 🎯 8. Customer Business Access Rules (`[business_rules]`)

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
| `blocked_ips` | Array | Client IP blacklist (listed IPs are dropped). |
| `required_headers` | Array | Mandatory HTTP headers required for request approval. |
| `max_body_bytes` | Integer | Maximum permitted HTTP body size in bytes. |
| `enabled` | Boolean | `true` to activate rule, `false` to disable. |

These rules are yours and live in your file. They are separate from cloud proposals: a
proposal you approve is stored in the ledger as a dynamic clause, not written into
`[business_rules]`.

---

## 🔑 9. Environment Variables Reference

| Variable | Description | Example |
| :--- | :--- | :--- |
| `SATGUARDIAN_CONFIG` | Overrides path to configuration file | `export SATGUARDIAN_CONFIG="/etc/waf_config.toml"` |
| `SATGUARDIAN_API_KEY` | Overrides the cloud API key (SU metering) | `export SATGUARDIAN_API_KEY="ek_live_12345"` |
| `SATGUARDIAN_ADMIN_TOKEN` | Bearer token for every management API route; without it the routes return `503` | `export SATGUARDIAN_ADMIN_TOKEN="$(openssl rand -hex 32)"` |
| `RUST_LOG` | Configures logging verbosity | `export RUST_LOG="info"` or `export RUST_LOG="satguardian_waf=debug"` |

Most TOML fields also accept a `WAF_*` override (`WAF_LISTEN_ADDR`, `WAF_UPSTREAM_URL`,
`WAF_MODE`, `WAF_STEALTH_MODE`, `WAF_ADMIN_LISTEN_ADDR`, `WAF_MAX_BODY_BYTES`,
`WAF_TRUSTED_PROXIES`, `WAF_DATABASE_PATH`, `ENVOY_EXT_AUTHZ_ADDR`,
`SATGUARDIAN_API_URL`), which wins over the file.

---

For the update loop (opt-in upload → proposals → your approval) and the CLI/Python
tooling, see [Operations & Tooling Guide](operations.md).

*© 2026 SATGuardian Cyber-Defense Systems. Edge enforcement is local and yours; SATGuardian cloud synthesis is opt-in and proposes, you approve.*
