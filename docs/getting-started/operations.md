# 📖 SATGuardian Edge WAF — Operations, Configuration & Tooling Manual

This guide documents **how to configure** and **operate** the **SATGuardian Edge WAF** client, and how to use the CLI subcommands and Python tools shipped in this repository.

**What the tiers mean:** free, you get local protection on your own node. Paying, you get continuous review of new patterns, update proposals and explanations — without ever giving up control of your WAF. Inspection and enforcement always run locally; the cloud is only consulted when you opt in, and what it returns is a proposal you approve or discard.

> **Status: SATGuardian Edge WAF v0.3.0.** Detection has been measured on small, hand-written,
> same-author corpora only. The in-sample rows (100% recall / 0% false positives) are
> regression floors from `corpus/independent_v1.json`, not generalization estimates. The
> current held-out estimate (`benchmarks/real_comparative/corpus/heldout_v10.jsonl`,
> run once on 2026-11-08, before any fix) froze the one-shot estimate in
> `heldout_v10_report.json` — recall on 70 attacks and **0.0% false positives on 44
> controls (95% CI 0.0–8.0%)**; the current engine measures 100%/0.0% on the same
> batch as a post-tuning diagnostic, and the earlier `heldout_v2` figure
> (56.1%/7.0%) remains for provenance. No third-party evaluation exists. The
> benchmark harness compares local Python stand-ins, not vendor products. See
> [STATUS.md](../status.md) and [corpus/README.md](../corpus.md).

---

## 📋 Table of Contents
1. [⚙️ WAF Configuration (`waf_config.toml` & Environment Variables)](#1-⚙️-waf-configuration-waf_configtoml--environment-variables)
2. [🔁 The Update Loop: Opt-In Cloud Review, Proposals & Approval](#2-🔁-the-update-loop-opt-in-cloud-review-proposals--approval)
3. [🛠️ Customization & Business Rules Guide](#3-🛠️-customization--business-rules-guide)
4. [🧰 Suite Applications & Tooling Guide](#4-🧰-suite-applications--tooling-guide)
   * [1. Main Engine Binary: `satguardian-waf` (Rust Engine & CLI)](#1-main-engine-binary-satguardian-waf-rust-engine--cli)
   * [2. Forensic Advisor & Digital Twin: `satguardian-advisor.py`](#2-forensic-advisor--digital-twin-satguardian-advisorpy)
   * [3. Business Rules & Islands Manager: `satguardian-rules.py`](#3-business-rules--islands-manager-satguardian-rulespy)
   * [4. Real-Time Terminal Dashboard: `satguardian-top.py`](#4-real-time-terminal-dashboard-satguardian-topy)
   * [5. Interactive Web Dashboard: `run_web.py`](#5-interactive-web-dashboard-run_webpy)
   * [6. Multi-WAF Comparative Benchmark Suite: `run_benchmark.py`](#6-multi-waf-comparative-benchmark-suite-run_benchmarkpy)
   * [7. Rule-Set Health Report: `satguardian-health.py`](#7-rule-set-health-report-satguardian-healthpy)

---

## 1. ⚙️ WAF Configuration (`waf_config.toml` & Environment Variables)

All local Edge WAF inspection settings are managed declaratively via `waf_config.toml` in the executable's working directory (or the path given by `--config` / `SATGUARDIAN_CONFIG`).

### 1.1 Core Network & Defense Mode Settings

```toml
# Inbound HTTP listener address for protected traffic
listen_addr = "0.0.0.0:8080"

# Target upstream backend application (Nginx, Node, Python, Go, Java, PHP, etc.)
upstream_url = "http://127.0.0.1:3000"

# Defense mode:
#   "block"   - Detected requests are rejected with HTTP 403.
#   "monitor" - Dry-run mode: violations are logged to the ledger and traffic passes.
mode = "block"
```

**Transport reality:** the data-plane listener speaks **plain HTTP**. This build does not
terminate TLS and does not support WebSocket; put nginx, Envoy or your existing load
balancer in front for TLS termination and keep the WAF on a private hop. `upstream_url`
may be `http://` or `https://` (the scheme is validated at startup) and calls to the
SATGuardian cloud endpoint go out over HTTPS — but nothing in this build serves HTTPS to
clients.

### 1.2 Anti-Reconnaissance Protection (Stealth Mode)

```toml
# true  -> Emits a clean web-standard 403 Forbidden without leaking rules, proof, or technology stacks.
# false -> Emits verbose diagnostic JSON containing the causal trace (debug mode).
stealth_mode = true

# Optional custom HTML or text response body when stealth_mode = true
# stealth_block_body = "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>"
```

Blocked responses are generic in stealth mode. Per request you can override the behaviour
from the command line: `satguardian-waf proxy --verbose` emits the diagnostic JSON,
`--stealth` forces the generic response.

### 1.3 Management API & Request Limits

```toml
# Dedicated listener for /api/waf/*. It is never mounted on the public data-plane port.
# Set to "off" to disable the management API entirely.
admin_listen_addr = "127.0.0.1:10001"

# Bearer token required by every management route. Prefer SATGUARDIAN_ADMIN_TOKEN
# in the environment over storing it here.
# admin_token = "change-me"

# Maximum accepted inbound request body (2 MiB).
max_body_bytes = 2097152

# IPs or CIDR ranges of upstream proxies allowed to supply X-Forwarded-For /
# X-Real-IP / CF-Connecting-IP / True-Client-IP. Loopback is always trusted.
trusted_proxies = []
```

* Every `/api/waf/*` route requires the admin token; with no token set the routes answer
  `503 management_api_disabled` instead of running unauthenticated. `/health` and `/livez`
  stay open on that listener.
* Request bodies are capped at `max_body_bytes` (2 MiB by default).
* The listener is loopback by default. If you must reach it from another host, put a
  TLS-terminating reverse proxy with its own authentication in front — the management API
  itself is plain HTTP.

### 1.4 Cloud Review Service (Security Units - SU) & SQLite Ledger

Boolean minimization is **server-side**. This repository ships the edge client only: it
normalizes a request into a 128-bit `FeatureVector` (`u128`), evaluates compiled clauses
locally, and — when you opt in — posts minterms to the SATGuardian cloud synthesis
endpoint and stores the returned equation as proposals. No minimizer lives in this code
base or in the client binary.

```toml
# SATGuardian cloud endpoint for Boolean rule synthesis.
satguardian_api_url = "https://satguardian.tech/api/simplify"

# Cloud API key (or set SATGUARDIAN_API_KEY in the environment).
# satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL ledger: audit log plus the table that holds update proposals.
database_path = "waf_ledger.db"

# Seconds between background cloud review runs. Only used when auto_sync_enabled is on.
autonomous_sync_interval_secs = 300

# Send anomalies to the cloud on that timer. Off by default. Turning it on does not
# change the WAF: results are stored as proposals and have to be approved with
# `satguardian-waf clauses apply` or POST /api/waf/clauses/{id}/apply.
auto_sync_enabled = false
```

**What leaves the node, and only if you opt in:** the `u128` feature vectors recorded as
novel anomalies (patterns awaiting analysis). Raw traffic, headers, bodies and client IPs
are not uploaded. Everything else — inspection, blocking, rate limiting, the ledger —
stays on your node.

**Quota behavior:** cloud synthesis is metered in Security Units (SU). If the balance is
exhausted the cloud call fails and the Edge WAF keeps enforcing the last rule matrix you
approved; local inspection is unaffected.

### 1.5 Layer-7 Stateful & Behavioral Defense (Rate Limiting & Anti-Brute Force)

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

### 1.6 Envoy Proxy Ext_Authz Integration

```toml
# Inbound HTTP listener for Envoy's envoy.filters.http.ext_authz filter
envoy_ext_authz_addr = "0.0.0.0:9002"
```

The check service speaks the HTTP form of `ext_authz` (it reads `x-envoy-original-method`
and `x-envoy-original-path`); the gRPC `ext_authz` protocol is not implemented in this
build. See `ENVOY_INTEGRATION_GUIDE.md`.

### 1.7 Modular Certainty Islands (`[islands]`)

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

### 1.8 Environment Variables Supported

| Variable | Effect |
| :--- | :--- |
| `SATGUARDIAN_CONFIG` | Path to the configuration TOML file. |
| `SATGUARDIAN_API_KEY` | Cloud API key for SATGuardian cloud synthesis (SU metering). |
| `SATGUARDIAN_ADMIN_TOKEN` (or `WAF_ADMIN_TOKEN`) | Bearer token for every management API route. Without it the routes answer `503`. |
| `RUST_LOG` | Tracing verbosity (e.g. `RUST_LOG=info` or `RUST_LOG=satguardian_waf=debug`). |

A `WAF_*` environment override exists for most TOML fields (`WAF_LISTEN_ADDR`,
`WAF_UPSTREAM_URL`, `WAF_MODE`, `WAF_STEALTH_MODE`, `WAF_ADMIN_LISTEN_ADDR`,
`WAF_MAX_BODY_BYTES`, `WAF_TRUSTED_PROXIES`, `WAF_DATABASE_PATH`, `ENVOY_EXT_AUTHZ_ADDR`,
`SATGUARDIAN_API_URL`); environment values win over the file.

---

## 2. 🔁 The Update Loop: Opt-In Cloud Review, Proposals & Approval

Nothing is uploaded and nothing changes in the running WAF unless you say so, twice.

1. **Local enforcement (free, always local).** Requests are normalized and evaluated
   against the compiled clauses on your node. Novel anomalies are recorded in
   `waf_ledger.db` as patterns awaiting analysis; recording them uploads nothing.
2. **Opt-in upload.** Set `auto_sync_enabled = true` to let a background timer send the
   recorded minterms to SATGuardian cloud synthesis every `autonomous_sync_interval_secs`
   seconds, or trigger one batch yourself:
   ```bash
   ./satguardian-waf sync-simplify --limit 100
   # or, on the admin listener:
   curl -X POST -H "Authorization: Bearer $SATGUARDIAN_ADMIN_TOKEN" \
     http://127.0.0.1:10001/api/waf/sync-simplify
   ```
3. **Results land as proposals.** A cloud review run stores what comes back with
   `dynamic_clauses.applied = 0`. Proposals do **not** enter the running engine, are not
   loaded at boot, and change nothing until you approve them.
4. **You decide.** Review each proposal and approve or discard it:
   ```bash
   ./satguardian-waf clauses list
   ./satguardian-waf clauses apply <clause_id>
   ./satguardian-waf clauses reject <clause_id>
   ```
   Or over the admin API (`GET /api/waf/clauses/pending`, `POST /api/waf/clauses/{id}/apply`,
   `DELETE /api/waf/clauses/{id}`), all behind the admin token.
5. **Approval is what makes a clause live.** Approving registers the clause in the running
   engine's in-memory dynamic-clause table, so new requests are evaluated against it
   immediately with no restart and no dropped TCP connections. If the proxy is stopped,
   approved clauses are the only proposals loaded at startup; pending ones stay pending. A
   clause that duplicates a mask already active, or exceeds the engine's dynamic-clause
   cap, is saved but will report that it enforces on restart instead of now. The hot list
   is a `RwLock`-protected clause table in `src/engine/sat_solver.rs`; there is no
   lock-free `ArcSwap` swap in this code base.
6. **Rejecting discards a proposal only.** It never deletes a rule that is already
   enforcing; enforced clauses are not touched by the reject path.

The same shape applies to the advisor: `satguardian-advisor.py` analyses the ledger and
proposes; applying anything is a separate, explicit operator action.

---

## 3. 🛠️ Customization & Business Rules Guide

SATGuardian allows fine-grained customization through two primary mechanisms: **Declarative Business Rules** and **Digital Twin Verification**.

### 3.1 Declarative Business Access Rules in `waf_config.toml`

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

### 3.2 Digital Twin Rule Verification

Before you approve a rule, `satguardian-advisor.py` can replay it against recorded history
(a **Digital Twin replay**):
1. Reads the benign HTTP transactions recorded in `waf_ledger.db`.
2. Evaluates candidate rules against that historical traffic and reports any collisions.
   Replay quality depends on the ledger contents; there is no fixed FPR floor.
3. Only after you approve does a clause reach active memory: it is registered in the
   engine's in-memory clause table and starts evaluating new requests, with no restart and
   no dropped TCP connections. Traffic is never hot-reloaded from the cloud by itself.

---

## 4. 🧰 Suite Applications & Tooling Guide

The repository ships one native Rust binary plus a set of Python CLI utilities for
analysis, administration, monitoring and benchmarking.

### 1. Main Engine Binary: `satguardian-waf` (Rust Engine & CLI)

Subcommands as implemented (`satguardian-waf --help` is authoritative). `--config` is a
global flag accepted by every subcommand.

#### A. Standalone Reverse Proxy Mode
```bash
# Launch the proxy using a configuration file
./satguardian-waf proxy --config waf_config.toml

# Or override the listener and upstream on the command line
./satguardian-waf proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000

# Mode and response verbosity
./satguardian-waf proxy --mode monitor --verbose
```
`proxy` also serves the management API on `admin_listen_addr` (`127.0.0.1:10001` by
default, `503` until `SATGUARDIAN_ADMIN_TOKEN` is set) and starts the background cloud
review timer only if `auto_sync_enabled = true`.

#### B. Native Benchmark Mode
Measures **in-memory** evaluation latency and CPU throughput over N synthetic requests
(default 10,000). It exercises the engine only: no TLS, no proxy hop, no upstream.
```bash
./satguardian-waf benchmark --requests 10000
```
Reference point: the pinned in-memory run over `corpus/independent_v1.json` at 10,000
requests measured about `~0.46 ms` p50 and `~0.9–1.0 ms` mean, with p99 `~6 ms` (re-measured 2026-11-10).
In-memory figures only — quote them as such.

#### C. Standalone Inspection Mode (CLI Payload Test)
Inspects a single request and prints its 128-bit `FeatureVector` (`u128`) and the decision
trace:
```bash
./satguardian-waf inspect --method POST --path /api/search \
  --query "id=1' UNION SELECT * FROM users--"
```

#### D. Cloud Review, One Batch at a Time
Sends the pending anomaly minterms to SATGuardian cloud synthesis and stores the result as
proposals. The running rule set is not changed by this command.
```bash
./satguardian-waf sync-simplify --limit 100
```

#### E. Approve or Discard Proposals
```bash
./satguardian-waf clauses list            # what is waiting for a decision
./satguardian-waf clauses apply <id>      # make it enforce
./satguardian-waf clauses reject <id>     # discard the proposal (never removes an active rule)
```

#### F. Envoy ext_authz Service and SafeLine T1K Co-Processor
```bash
./satguardian-waf envoy-authz --listen 0.0.0.0:9002
./satguardian-waf envoy-authz --socket /var/run/waf.sock

./satguardian-waf t1k-server --listen 0.0.0.0:8000   # SafeLine T1K protocol
```

#### G. Cloud Account Status
Checks the SU balance and the edge entitlement reported by the cloud:
```bash
./satguardian-waf entitlement
```

> There is no separate `api` subcommand: the management API runs inside `proxy` on the
> loopback admin listener described in §1.3.

---

### 2. Forensic Advisor & Digital Twin: `satguardian-advisor.py`

Analyses recorded transactions in `waf_ledger.db`, clusters novel patterns (patterns
awaiting analysis), replays candidate rules against the ledger, and produces
**evidence-backed audit reports**. It analyses and proposes — applying anything stays an
explicit operator action.

#### Usage:
```bash
# Evidence-backed audit report in interactive HTML format
python satguardian-advisor.py --report audit_report.html

# Same report in Markdown
python satguardian-advisor.py --report-md audit_report.md

# Custom SQLite ledger path
python satguardian-advisor.py --db /path/to/custom_ledger.db --report custom_report.html

# Analyse and list suggestions without prompting to apply anything
python satguardian-advisor.py --dry-run
```

---

### 3. Business Rules & Islands Manager: `satguardian-rules.py`

Interactive manager for `[business_rules]` and `[islands]`: list, add, toggle and delete
customer rules, flip islands, run a live inspection through the management API, and drive
the advisor. It writes changes into `waf_config.toml` as well.

#### Usage:
```bash
python satguardian-rules.py            # curses TUI (Linux/macOS, or windows-curses)
python satguardian-rules.py --cli      # ANSI console menu when curses is unavailable
```

Two limits worth knowing:
* The tool has no subcommands — `satguardian-rules.py list` does not exist; the menu is
  interactive.
* It calls the management API but does not send the admin token, and its default `--api`
  value is `http://127.0.0.1:10000` while the WAF binds `127.0.0.1:10001`. Point it at the
  admin listener with `--api http://127.0.0.1:10001`; API-backed actions only work once the
  management API is enabled with `SATGUARDIAN_ADMIN_TOKEN`, and the tool has no way to pass
  that token, so editing `waf_config.toml` through the tool (option 8) is the path that
  works against a token-protected listener.

---

### 4. Real-Time Terminal Dashboard: `satguardian-top.py`

`htop`-style terminal monitor that reads `waf_ledger.db` directly: throughput (req/sec),
recorded evaluation latencies (µs), and the blocked-attack distribution by category and
source IP. It is local and read-only — it opens no socket and uploads nothing.

The latencies shown are the in-memory evaluation times recorded per request by the engine;
they exclude TLS, proxy hops and upstream time.

#### Usage:
```bash
python satguardian-top.py                     # auto-discovers the ledger
python satguardian-top.py --db /var/lib/satguardian/waf_ledger.db --rate 0.5 --blocks-only
```

---

### 5. Interactive Web Dashboard: `run_web.py`

Serves the PoC dashboard and duel simulator from `satguardian_waf/web` with FastAPI/uvicorn
(not Streamlit, and there is no `app.py`): visual telemetry over the Python reference
engine, attack trend charting and rule inspection.

#### Usage:
```bash
python run_web.py 8002
```
Open `http://localhost:8002`. The dashboard exercises the Python reference implementation,
not the Rust engine.

---

### 6. Multi-WAF Comparative Benchmark Suite: `run_benchmark.py`

Runs the Python reference harness against local Python stand-ins for CRS-style,
semantic-token, raw-regex and probabilistic techniques. **It does not execute
Coraza, SafeLine, ModSecurity or a trained NLP model.** The dataset is the small
in-repo payload list, and the report prints provenance and a disclaimer.

#### Usage:
```bash
# Run comparative benchmark across 1,000 requests
python run_benchmark.py 1000
```

---

### 7. Rule-Set Health Report: `satguardian-health.py`

Local, read-only audit of the rule set you wrote: inventory of business rules and islands
(enabled vs disabled), structural findings (duplicate ids, a rule that both allows and
blocks the same method, duplicate bodies, contradicting overlapping path prefixes) and a
summary of what the ledger recorded. It reads `waf_config.toml` and `waf_ledger.db`, opens
no socket and uploads nothing — it is part of the free tier and works with no cloud account.

#### Usage:
```bash
python satguardian-health.py                       # text report from the current directory
python satguardian-health.py --json                 # machine-readable
python satguardian-health.py --config /etc/satguardian/waf_config.toml --db /var/lib/satguardian/waf_ledger.db
python satguardian-health.py --strict --top 10      # exit 1 if any WARN finding is present
```

---

## 🎯 Quick Command Cheat Sheet

| Task / Objective | Command |
| :--- | :--- |
| **Standalone Proxy** | `./satguardian-waf proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000` |
| **Native Rust Benchmark (in-memory)** | `./satguardian-waf benchmark --requests 10000` |
| **Payload CLI Inspection** | `./satguardian-waf inspect --query "search=union select"` |
| **Cloud review (one batch → proposals)** | `./satguardian-waf sync-simplify --limit 100` |
| **List / approve / reject proposals** | `./satguardian-waf clauses list` · `clauses apply <id>` · `clauses reject <id>` |
| **Check SU balance** | `./satguardian-waf entitlement` |
| **Evidence-backed audit report** | `python satguardian-advisor.py --report audit_report.html` |
| **Business Rules & Islands Manager** | `python satguardian-rules.py --cli` |
| **Read-Only Terminal TUI** | `python satguardian-top.py` |
| **Web Dashboard (FastAPI)** | `python run_web.py 8002` |
| **Multi-WAF Benchmark Suite** | `python run_benchmark.py 1000` |
| **Local Rule-Set Health Report** | `python satguardian-health.py` |

---

*© 2026 SATGuardian Cyber-Defense Systems. Edge enforcement is local and yours; SATGuardian cloud synthesis is opt-in and proposes, you approve.*
