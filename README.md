# 🛡️ SATGuardian Edge WAF (`satguardian`)

> **Status: research prototype, not a production-ready WAF.**
> Detection has only been measured on a small, hand-written, in-sample corpus.
> The Python comparison harness runs local stand-ins, not real Coraza, SafeLine
> or ModSecurity. See [STATUS.md](STATUS.md) and [corpus/README.md](corpus/README.md)
> for the evidence and its limits.

**📚 Official Documentation:** [https://exactorresearch.github.io/satguardian/](https://exactorresearch.github.io/satguardian/)

[![Architecture](https://img.shields.io/badge/Architecture-Lexical_&_Bitmask_WAF-blue.svg)](#2-consideration-the-solution--satguardian-architecture)
[![Performance](https://img.shields.io/badge/Hot_Path-In--Memory_p50_~20_µs-brightgreen.svg)](#3-decision-in-sample-measurements-business-value)
[![Synthesis](https://img.shields.io/badge/Rule_Synthesis-EXACTOR_GXOR_(128_Vars)-orange.svg)](#22-out-of-band-cloud-synthesis-exactor-gxor)
[![License](https://img.shields.io/badge/Edge_WAF-100%25_Free_&_Unlimited_Traffic-success.svg)](#33-pricing--licensing-zero-traffic-tax)

**SATGuardian Edge WAF** is an experimental, self-hosted Web Application Firewall
written in Rust. It evaluates security logic with **128-bit integer bitmasks
(`u128`)** in microseconds on the edge, backed by out-of-band **EXACTOR GXOR**
boolean cloud optimization. Detection quality is **measured, not assumed**: the
numbers below come from a versioned corpus and a reproducible benchmark, and they
are explicitly in-sample.

---

## ⚡ Quick Start: Standalone Binary Test Drive (60 Seconds)

Evaluate SATGuardian Edge WAF in **Standalone Mode** with **zero external dependencies** using the pre-compiled binary:

### 1️⃣ Download the Pre-Compiled Standalone Binary

Download the self-contained binary for your platform (no Rust runtime, Node, or compilers required):

* **Linux (x86_64 / glibc):**
  ```bash
  curl -L -O https://github.com/SATGuardian/satguardian/releases/download/v0.3.0/satguardian-waf-linux-amd64
  chmod +x satguardian-waf-linux-amd64
  ```
* **Windows (x64 PowerShell):**
  ```powershell
  Invoke-WebRequest -Uri "https://github.com/SATGuardian/satguardian/releases/download/v0.3.0/satguardian-waf-v0.3.0.exe" -OutFile "satguardian-waf.exe"
  ```

### 2️⃣ Launch the Standalone Reverse Proxy & Test Live Threat Detection

Spin up SATGuardian as a standalone frontline proxy and test real-time attack blocking with `curl`:

```bash
# Terminal A: Start standalone WAF proxy on port 8080 forwarding to your application (port 3000)
./satguardian-waf proxy --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000

# Terminal B: Test a benign request (Allowed -> HTTP 200 OK)
curl -i http://localhost:8080/api/users?search=john_doe

# Terminal B: Test a SQLi + XSS multi-vector attack (Blocked -> HTTP 403 Forbidden)
curl -i "http://localhost:8080/api/users?search=1%27%20UNION%20SELECT%20*%20FROM%20users--%20%3Cscript%3Ealert(1)%3C/script%3E"
```

### 3️⃣ Run the Built-In Standalone Benchmark (10,000 Requests)

Measure real single-core CPU throughput and sub-millisecond bitmask evaluation latency directly with the standalone binary:

```bash
# Windows
.\satguardian-waf.exe benchmark -r 10000

# Linux
./satguardian-waf benchmark -r 10000
```

*(Note: Developers can also build directly from source using `cargo run --release -- benchmark -r 10000`)*

---

## 1. Awareness: The Problem with Traditional WAFs

Modern API gateways, microservices, and web applications face an impossible security trade-off:

```
                  ┌─────────────────────────────────────────┐
                  │ THE TRADITIONAL WAF DILEMMA             │
                  └─────────────────────────────────────────┘
                                       │
        ┌──────────────────────────────┴──────────────────────────────┐
        ▼                                                             ▼
┌──────────────────────────────┐                            ┌──────────────────────────────┐
│  Regex & Anomaly Scoring     │                            │  Probabilistic "AI/ML" WAFs  │
│  (ModSecurity / Coraza CRS)  │                            │  (NLP / Token Weights)       │
├──────────────────────────────┤                            ├──────────────────────────────┤
│ ❌ Heavy CPU Overhead        │                            │ ❌ High False Positive Rates │
│    (rule-set dependent)      │                            │    (Blocks technical prose)  │
│ ❌ Evasion Vulnerability     │                            │ ❌ Unpredictable Box Black   │
│    (Triple URL / Comment)    │                            │    (Zero auditability)       │
└──────────────────────────────┘                            └──────────────────────────────┘
```

1. **The Latency Tax of Rule Sets:** Evaluating many regular expressions across
   multiple HTTP targets (URI, headers, body) adds CPU work to every request.
   How much depends on the rule set, paranoia level and hardware; this repository
   does not benchmark the real OWASP CRS, so no vendor latency number is claimed.
2. **Evasion via Obfuscation:** Single-pass regex engines can miss nested
   encodings (`..%25252f`), inline comments (`UNION/**/SELECT`) and DOM event
   mutations. The local unnormalized-regex stand-in misses 47.0% of attacks on
   the in-repo stream; that figure describes the stand-in, not ModSecurity.
3. **The False Positive Problem:** Token-weight classifiers can flag technical
   prose such as `"script"`, `"select"` or `"character"`. The local heuristic
   stand-in blocks 24.6% of benign controls on the in-repo stream; it is not a
   trained model and does not represent a commercial classifier.

---

## 2. Consideration: The Solution — SATGuardian Architecture

SATGuardian resolves this dilemma by decoupling **in-path edge inspection** from **out-of-band boolean rule synthesis**.

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. HOT PATH: SOVEREIGN EDGE WAF (100% On-Premise, Unlimited Free Traffic)  │
│                                                                            │
│  HTTP Request ──► Multi-Pass Lexer ──► 128-Bit FeatureVector (u128)        │
│                   (src/ast/lexer.rs)   (src/ast/features.rs)               │
│                                                 │                          │
│                                                 ▼                          │
│                                 Bitwise Rule Mask Evaluation               │
│                                 (minterm & mask) == expected               │
│                                 (~20 µs p50 in-memory, native Rust)        │
│                                        /               \                   │
│                                   [ALLOW]             [BLOCK + Causal Log] │
└─────────────────────────────────────────────────────────┬──────────────────┘
                                                          │ Async SQLite
                                                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CONTROL PLANE: OFFLINE ADVISOR & CLOUD SYNTHESIS (Security Units - SU) │
│                                                                            │
│  waf_ledger.db ──► EXACTOR GXOR (AND, OR, NOT, XOR)    ──► Digital Twin    │
│  (3,799 logs)      128-Variable Boolean Minimization       Replay (FP gate) │
│                    (src/cloud/satguardian_client.rs)             │         │
│                                                                  ▼         │
│                                                   Atomic ArcSwap Hot-Reload│
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Native Rust In-Path Edge Engine (`src/`)

* **Multi-Pass Lexical Normalization (`src/ast/lexer.rs`):** Applies percent-decoding, unwraps MySQL executable comments, strips inline comments, decodes HTML entities and Unicode/overlong escapes, and expands Log4j lookups before token extraction. Entity-encoded payloads are covered by `corpus/independent_v1.json`; that is a regression check, not proof of complete coverage.
* **128-Bit Feature Vector (`src/ast/features.rs`):** Packs HTTP attributes, Shannon character entropy, and structural tokens across 5 domains (`SQLi`, `XSS`, `RCE`, `LFI`, `SSRF`) into a single `u128` integer.
* **Bitmask Conjunction Evaluation (`src/engine/sat_solver.rs`):** Compares request minterms against compiled rule masks via bitwise `AND` operations (`(minterm & required_mask) == expected_bits`). On the pinned corpus at 10,000 requests the native engine measured roughly `20 µs` p50 and `22–25 µs` mean in-memory; p99 is load dependent and has measured `50–60 µs`.
* **Structural token conjunctions:** Rules require combinations such as `TAG_OPEN` $\land$ `SCRIPT_ELEMENT` $\land$ `DOM_EXEC` instead of single keywords. False positives are counted on the pinned corpus; the engine does not claim zero FPs.

### 2.2 Out-of-Band Cloud Synthesis: EXACTOR GXOR (`src/cloud/satguardian_client.rs`)

When novel attack patterns are recorded in `waf_ledger.db`, SATGuardian sends the 128-bit minterms to the **EXACTOR GXOR** cloud optimization engine:
* **Linear $O(\text{term\_count})$ Scaling:** Uses Differential Gray Code Mapping (`modify_gray_code`) to locate logical neighbors in $O(1)$ constant time, avoiding the $O(2^n)$ exponential blow-up of classical Quine-McCluskey / Espresso minimizers.
* **Full Operator Basis `{AND, OR, NOT, XOR}`:** Minimizes parity, equivalence, and symmetric security predicates across **up to 128 variables (`u128`)**. The size reduction versus a naive Sum-of-Products expansion is not measured in this repository.
* **Digital Twin Replay:** Replays candidate rules against recorded benign traffic (`satguardian-advisor.py`), reports collisions, and requires human approval before hot-reloading via lock-free `ArcSwap`.

---

## 3. Decision: In-Sample Measurements & Business Value

The figures below are **in-sample** measurements from this repository's own payload set. The "competitor" agents are small Python regex stand-ins, not the real Coraza, SafeLine or ModSecurity products, so these numbers are useful for regression tracking rather than for procurement claims.

> **Correction notice:** Earlier releases capped perfect scores at 99.9%, floored
> zero error rates at 0.1%, and labelled local Python regex stand-ins as Coraza
> and SafeLine. Those claims were fabricated or misleading. The cap/floor logic
> has been removed, the stand-ins are labelled, and the Rust benchmark now reads
> `corpus/independent_v1.json` instead of an ad-hoc payload list.

### 3.1 Python stand-in harness (`1,000` sampled requests, 50% attacks)

Run with `python run_benchmark.py 1000`. Only the SATGuardian row is this
project's code; every other row is a local Python reimplementation, not the
named product.

| Agent (all Python, in-process) | Accuracy (in-sample) | Avg CPU time | P99 CPU time | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **SATGuardian reference port** | **100.0%** | **`0.0586 ms`** | **`0.2267 ms`** | **0.0%** | **0.0%** |
| CRS-style stand-in (not Coraza) | 97.3% | `0.2350 ms` | `0.5244 ms` | 0.0% | 5.4% |
| Semantic-token stand-in (not SafeLine) | 94.4% | `0.0637 ms` | `0.1618 ms` | 0.0% | 11.2% |
| Probabilistic token stand-in (hand-written heuristic) | 77.3% | `0.0726 ms` | `0.1708 ms` | 24.6% | 20.8% |
| Unnormalized regex stand-in (not ModSecurity) | 76.5% | `0.0383 ms` | `0.0792 ms` | 0.0% | 47.0% |

### 3.2 Rust engine on the pinned corpus (`cargo run --release -- benchmark -r 10000`)

| Engine | Reproduced from | Latency (in-memory) | Corpus result |
| :--- | :--- | :---: | :---: |
| Native Rust v0.3.0 | `corpus/independent_v1.json`, 10,000 requests (representative run) | p50 `~20 µs`, mean `~22–25 µs`, p99 `~50–60 µs` | 63/63 attacks, 0/16 benign blocked |

* **Speed is in-memory only.** No TLS, proxy hop, upstream or stateful tracking
  is included. The Python reference port ran at `58.6 µs` versus `235.0 µs` for
  the CRS-style stand-in on the same stream; that compares two Python programs,
  not SATGuardian against Coraza.
* **Detection quality is a regression floor, not an estimate.** First run of the
  independent corpus scored 51/63 (80.95% recall) with 3/16 benign blocked
  (18.75% FPR). A second batch scored 11/17 (64.71%) on its first run. After the
  fixes both report 100%/0%, but every case was used to drive those fixes, so
  the result is in-sample. Details: [corpus/README.md](corpus/README.md).
* **No production evidence exists.** There is no third-party evaluation, no soak
  test, and no real-product comparison. See [STATUS.md](STATUS.md).

### 3.3 100% On-Premise Traffic Sovereignty

SATGuardian runs **entirely inside your infrastructure**. We **never** host customer traffic or require DNS CNAME redirects:

1. **Kubernetes / Envoy Proxy Native Sidecar:** Runs alongside Envoy via `ext_authz` over an in-memory Unix Domain Socket (`unix:///run/satguardian/waf.sock`), adding the engine's measured per-request latency (tens of microseconds) with no network hop.
2. **Reverse Proxy:** Frontline protection for Nginx, Apache, or Microsoft IIS (including Windows Service deployment via `install.ps1`).
3. **Standalone Binary:** Zero-dependency, self-contained Rust binary (`satguardian-waf proxy --listen 127.0.0.1:8080`). It speaks plain HTTP; terminate TLS in a reverse proxy or Envoy in front of it.

### 3.4 Pricing & Licensing: Zero Traffic Tax

| Plan | Monthly Price | Seats | Complexity Limit | Included Security Units (SU) | Extra SU Overage Rate |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SCOUT** | **$20 USD** | 1 | Up to 20 vars / 2.5K minterms | 1,000 SU / mo | Cloud synthesis pauses on quota exhaustion |
| **PRO / DEV** | **$49 USD** | 1 | Up to 64 vars / 10K minterms | 5,000 SU / mo | $10 USD per 1,000 extra SU |
| **STARTUP** | **$499 USD** | 5 | Up to 128 vars / 100K minterms | 50,000 SU / mo | $8 USD per 1,000 extra SU |
| **SCALE** | **$2,499 USD** | 15 | Up to 128 vars / 1M minterms | 500,000 SU / mo | $5 USD per 1,000 extra SU |
| **ENTERPRISE** | **Custom** | Unlimited | Up to 128 vars / Unlimited | Custom annual pool | Custom SLA & Dedicated Contract |

> **Quota behavior:** The local Edge WAF is **100% free and unlimited** ($0.00/request). You pay only for Cloud Boolean Optimization metered in **Security Units (SU)**. If monthly SU quotas are exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud synthesis pauses and the local Edge WAF keeps serving traffic with its last compiled rule matrix. *(Note: 256+ variable matrices are managed exclusively as dedicated Engineering Expansion Projects on Bare-Metal/HPC hardware).*

---

## 4. Action: Getting Started in 4 Easy Steps

Follow this step-by-step onboarding journey to evaluate SATGuardian in your environment:

### Step 1: Download & Run the Standalone Binary Benchmark (30 Seconds)

Test the self-contained standalone binary directly on your machine across 10,000 HTTP requests with zero dependencies:

```powershell
# Using pre-compiled standalone binary
.\satguardian-waf.exe benchmark -r 10000

# Or building directly from source via cargo
cargo run --release -- benchmark -r 10000
```

### Step 2: Run the Multi-WAF Comparative Benchmark

Run the Python reference harness against the local stand-ins:

```powershell
python run_benchmark.py 1000
```

This does not execute Coraza, SafeLine, ModSecurity or an LLM. It compares the
Python SATGuardian port with small Python reimplementations on the in-repo
payload list. The report prints the provenance and the caveat.

### Step 3: Deploy in Staging / Local Envoy Sidecar

Launch the standalone reverse proxy or attach SATGuardian to your Envoy proxy via `ext_authz`:

```bash
# Standalone reverse proxy. It speaks plain HTTP: terminate TLS in front of it.
# The management API is isolated on 127.0.0.1:10001 and requires a bearer token.
export SATGUARDIAN_ADMIN_TOKEN="$(openssl rand -hex 32)"
satguardian-waf proxy --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000

# Daily example: inspect metrics from the local management listener
curl -H "Authorization: Bearer $SATGUARDIAN_ADMIN_TOKEN" \
  http://127.0.0.1:10001/api/waf/metrics
```

**Security defaults introduced in this release:**

* Management routes (`/api/waf/*`) return `503` until `SATGUARDIAN_ADMIN_TOKEN` (or `WAF_ADMIN_TOKEN`) is set.
* The management API listens only on `127.0.0.1:10001`; set `WAF_ADMIN_LISTEN_ADDR` to change it or `off` to disable it.
* Inbound bodies are capped at 2 MiB (`WAF_MAX_BODY_BYTES`); larger requests get `413`.
* Forwarding headers are ignored unless the TCP peer is in `WAF_TRUSTED_PROXIES` (loopback is always trusted).
* Blocked responses are generic by default. Use `--verbose` only in development.
* Upstream responses are streamed, so SSE and large downloads are no longer buffered. WebSocket upgrades are not supported yet.

### Step 4: Generate Forensic Audit Reports & Schedule a Technical Demo

Analyze recorded transactions in `waf_ledger.db`, verify synthesized rules with the Digital Twin, and generate executive HTML/Markdown compliance reports:

```powershell
python satguardian-advisor.py --report audit_report.html
python satguardian-advisor.py --report-md audit_report.md
```

* **Full Operations & Configuration Guide:** Read the [Official Documentation](https://exactorresearch.github.io/satguardian/) for detailed configuration, customization, and tool usages.
* **Explore the Interactive Dashboard:** `streamlit run app.py`
* **Schedule a Technical Demo & Architecture Review:** Contact our engineering team at [satguardian.tech](https://satguardian.tech) or open an issue on GitHub.

---

*© 2026 SATGuardian Cyber-Defense Systems. Sovereign Edge Security Powered by Native Rust & EXACTOR GXOR.*
