# 📖 SATGuardian Edge WAF — Complete Operations, Configuration & Tooling Manual

This guide provides exhaustive documentation on **how to configure**, **customize**, and **utilize the complete suite of additional tools and CLI applications** comprising the **SATGuardian Edge WAF** cyber-defense platform.

---

## 📋 Table of Contents
1. [WAF Configuration (`waf_config.toml` & Environment Variables)](#1-waf-configuration-waf_configtoml-environment-variables)
2. [Customization & Business Rules Guide](#2-customization-business-rules-guide)
3. [Suite Applications & Tooling Guide](#3-suite-applications-tooling-guide)
   * [1. Main Engine Binary: `satguardian-waf` (Rust Engine & CLI)](#1-main-engine-binary-satguardian-waf-rust-engine-cli)
   * [2. Forensic Advisor & Digital Twin: `satguardian-advisor.py`](#2-forensic-advisor-digital-twin-satguardian-advisorpy)
   * [3. Business Rules Management CLI: `satguardian-rules.py`](#3-business-rules-management-cli-satguardian-rulespy)
   * [4. Real-Time Terminal Dashboard: `satguardian-top.py`](#4-real-time-terminal-dashboard-satguardian-toppy)
   * [5. Interactive Web Dashboard: `app.py` / `run_web.py` (Streamlit)](#5-interactive-web-dashboard-apppy-run_webpy-streamlit)
   * [6. Multi-WAF Comparative Benchmark Suite: `run_benchmark.py`](#6-multi-waf-comparative-benchmark-suite-run_benchmarkpy)

---

## 1. ⚙️ WAF Configuration (`waf_config.toml` & Environment Variables)

All local Edge WAF inspection settings are managed declaratively via `waf_config.toml` in the executable's working directory.

### 1.1 Core Network & Defense Mode Settings

```toml
# Inbound HTTP listener address for protected traffic
listen_addr = "0.0.0.0:8080"

# Target upstream backend application (Nginx, Node, Python, Go, Java, PHP, etc.)
upstream_url = "http://127.0.0.1:3000"

# Defense mode:
#   "block"   - Active perimeter defense: instantly drops attacks with HTTP 403.
#   "monitor" - Passive / dry-run mode: logs violations but permits traffic upstream.
mode = "block"
```

### 1.2 Anti-Reconnaissance Protection (Stealth Mode)

```toml
# true  -> Emits clean web-standard 403 Forbidden without leaking rules, proof, or technology stacks.
# false -> Emits verbose diagnostic JSON containing formal causal proofs (debug mode).
stealth_mode = true

# Optional custom HTML or text response body when stealth_mode = true
# stealth_block_body = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>"
```

### 1.3 Cloud Optimization Service (Security Units - SU) & SQLite Ledger

```toml
# SATGuardian Cloud Optimization API URL for Autonomous EXACTOR GXOR Boolean Minimization
satguardian_api_url = "https://satguardian.tech/api/simplify"

# Cloud API Key (or configure via SATGUARDIAN_API_KEY environment variable)
satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL Ledger database path for audit logging and anomaly clustering
database_path = "waf_ledger.db"

# Autonomous background minimization sync interval in seconds (default: 300s / 5 mins)
autonomous_sync_interval_secs = 300

# Enable automatic hot-reload minimization sync with satguardian.tech
auto_sync_enabled = true
```

### 1.4 Layer-7 Stateful & Behavioral Defense (Rate Limiting & Anti-Brute Force)

```toml
# Enable temporal sliding window ring buffer analysis
stateful_enabled = true

# Max total requests permitted in sliding window per IP across all endpoints
stateful_global_limit = 300

# Max attempts permitted on sensitive authentication endpoints (/login, /auth, etc.)
stateful_auth_limit = 20

# Sliding temporal window duration in seconds (default: 60s ring buffer)
stateful_window_secs = 60

# Temporary isolation quarantine / jail duration in seconds for offenders (180s)
stateful_ban_secs = 180

# Optional Redis connection URL for distributed cluster state synchronization
# redis_url = "redis://127.0.0.1:6379"
```

### 1.5 Envoy Proxy Ext_Authz Integration

```toml
# Inbound HTTP listener for Envoy's envoy.filters.http.ext_authz filter
envoy_ext_authz_addr = "0.0.0.0:9002"
```

### 1.6 Modular Certainty Islands (`[islands]`)

```toml
[islands]
# WordPress Reconnaissance & Exploit Shield:
# Drops scanner probes targeting /wp-admin, /wp-login.php, xmlrpc.php, etc.
wordpress_shield = true

# Sensitive Files & Backdoors Shield:
# Blocks discovery probes targeting /.env, /.git, phpMyAdmin, actuator, backup dumps.
exposure_shield = true

# Modern Framework Exploits Shield:
# Blocks Log4j/JNDI injection, Spring Cloud SpEL, Laravel Ignition, ThinkPHP probes.
framework_shield = true
```

### 1.7 Environment Variables Supported

* `SATGUARDIAN_CONFIG`: Custom path to configuration TOML file.
* `SATGUARDIAN_API_KEY`: Authentication key for Cloud Boolean Optimization (SU metering).
* `RUST_LOG`: Log level tracing verbosity (e.g. `RUST_LOG=info` or `RUST_LOG=debug`).

---

## 2. 🛠️ Customization & Business Rules Guide

SATGuardian allows fine-grained customization through two primary mechanisms: **Declarative Business Rules** and **Digital Twin Verification**.

### 2.1 Declarative Business Access Rules in `waf_config.toml`

Define granular access policies per path prefix, HTTP method, client IP whitelist/blacklist, and mandatory headers under `[business_rules]`:

```toml
[business_rules]
enabled = true

# Example Rule 1: Strict API Method Restrictions
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

# Example Rule 2: IP-Whitelisted Administrative Gateway
[[business_rules.rules]]
id = "biz-admin-gateway"
name = "Admin Portal IP Restricted Access"
path_prefix = "/internal/admin/"
allowed_methods = ["GET", "POST"]
blocked_methods = []
allowed_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.100"]
blocked_ips = []
required_headers = ["X-Admin-Token"]
max_body_bytes = 1048576 # 1 MB
enabled = true
```

### 2.2 Digital Twin Rule Verification

Before any custom or synthesized rule matrix is deployed into active memory, SATGuardian executes a **Digital Twin replay** (`satguardian-advisor.py`):
1. Reads all recorded benign HTTP transactions in `waf_ledger.db`.
2. Evaluates candidate rules against historical legitimate traffic to certify **`< 0.1%` False Positive Rate**.
3. Hot-reloads verified rule masks into active memory using lock-free `ArcSwap` without dropping active TCP connections.

---

## 3. 🧰 Suite Applications & Tooling Guide

The platform includes a comprehensive suite of native Rust binaries and Python CLI utilities for administration, monitoring, testing, and benchmarking.

### 1. Main Engine Binary: `satguardian-waf` (Rust Engine & CLI)

The compiled high-performance native binary supports multiple operational subcommands:

#### A. Standalone Reverse Proxy Mode
```bash
# Launch proxy using default configuration file
./satguardian-waf proxy --config waf_config.toml

# Quick CLI standalone proxy launch
./satguardian-waf proxy --listen 0.0.0.0:8080 --upstream 127.0.0.1:3000
```

#### B. Native Benchmark Mode
Measures sub-millisecond evaluation latency and CPU throughput across 10,000 in-memory requests:
```bash
./satguardian-waf benchmark -r 10000
```

#### C. Standalone Inspection Mode (CLI Payload Test)
Inspects a specific payload, displaying its 128-bit `FeatureVector` (`u128`) and decision causal trace:
```bash
./satguardian-waf inspect --query "id=1' UNION SELECT * FROM users--"
```

#### D. WAF API Management Server
Launches the internal REST management server for health checks and rule status:
```bash
./satguardian-waf api --listen 0.0.0.0:8081
```

---

### 2. Forensic Advisor & Digital Twin: `satguardian-advisor.py`

Security intelligence agent that analyzes recorded transactions in `waf_ledger.db`, clusters novel attack patterns, verifies rules against the Digital Twin, and generates executive compliance reports.

#### Usage:
```bash
# Generate executive forensic audit report in interactive HTML format
python satguardian-advisor.py --report audit_report.html

# Generate report in Markdown format
python satguardian-advisor.py --report-md audit_report.md

# Specify custom SQLite audit ledger path
python satguardian-advisor.py --db /path/to/custom_ledger.db --report custom_report.html
```

---

### 3. Business Rules Management CLI: `satguardian-rules.py`

CLI management tool to list, create, enable, disable, and remove custom customer access rules directly in `waf_ledger.db`.

#### Usage:
```bash
# List all active and registered business rules
python satguardian-rules.py list

# Add a new IP-restricted administrative route rule
python satguardian-rules.py add \
  --id biz-admin-panel \
  --name "Admin Access Restriction" \
  --path "/admin/" \
  --methods "GET,POST" \
  --ips "192.168.1.50,10.0.0.1" \
  --headers "X-Internal-Secret"

# Disable an existing rule
python satguardian-rules.py disable --id biz-admin-panel

# Delete a rule
python satguardian-rules.py delete --id biz-admin-panel
```

---

### 4. Real-Time Terminal Dashboard: `satguardian-top.py`

Interactive terminal interface (`htop` style) for real-time monitoring of WAF health, throughput (req/sec), $p50$/$p99$ CPU latencies, and blocked attack distribution by vector and source IP.

#### Usage:
```bash
python satguardian-top.py
```

---

### 5. Interactive Web Dashboard: `app.py` / `run_web.py` (Streamlit)

Browser-based graphical UI for visual telemetry analysis of `waf_ledger.db`, attack trend charting, active rule inspection, and triggering cloud minimization cycles.

#### Usage:
```bash
# Launch web dashboard via wrapper script
python run_web.py

# Or run directly with Streamlit
streamlit run app.py
```
Access the web dashboard in your browser at `http://localhost:8501`.

---

### 6. Multi-WAF Comparative Benchmark Suite: `run_benchmark.py`

Executes a reproducible empirical benchmark comparing **SATGuardian Edge WAF** against 4 popular security engines (**OWASP CRS v4 / Coraza**, **SafeLine T1K**, **ModSecurity Regex**, and **Probabilistic NLP Classifier**).

#### Usage:
```bash
# Run comparative benchmark across 1,000 requests
python run_benchmark.py 1000
```

---

## 🎯 Quick Command Cheat Sheet

| Task / Objective | Command |
| :--- | :--- |
| **Standalone Proxy (60s Test Drive)** | `./satguardian-waf proxy --listen 0.0.0.0:8080 --upstream 127.0.0.1:3000` |
| **Native Rust Benchmark** | `./satguardian-waf benchmark -r 10000` |
| **Payload CLI Inspection** | `./satguardian-waf inspect --query "search=union select"` |
| **HTML Audit Report Generation** | `python satguardian-advisor.py --report audit_report.html` |
| **Business Rules Management** | `python satguardian-rules.py list` |
| **Real-Time Terminal TUI** | `python satguardian-top.py` |
| **Interactive Web Dashboard** | `streamlit run app.py` |
| **Multi-WAF Benchmark Suite** | `python run_benchmark.py 1000` |

---

*© 2026 SATGuardian Cyber-Defense Systems. Sovereign Edge Security Powered by Native Rust & EXACTOR GXOR.*
