# 🛡️ SATGuardian Edge WAF (`satguardian`)

> **Status: SATGuardian Edge WAF v0.3.0.**
> Detection has only been measured on a small, hand-written, in-sample corpus.
> The Python comparison harness runs local stand-ins, not real Coraza, SafeLine
> or ModSecurity. See [STATUS.md](STATUS.md) and [corpus/README.md](corpus/README.md)
> for the evidence and its limits.

**📚 Official Documentation:** [https://exactorresearch.github.io/satguardian/](https://exactorresearch.github.io/satguardian/)

[![Architecture](https://img.shields.io/badge/Architecture-Lexical_&_Bitmask_WAF-blue.svg)](#2-consideration-the-solution--satguardian-architecture)
[![Performance](https://img.shields.io/badge/Hot_Path-In--Memory_p50_~0.46_ms-brightgreen.svg)](#3-decision-what-has-been-measured)
[![Synthesis](https://img.shields.io/badge/Rule_Synthesis-Opt--in_Cloud%2C_Approved_locally-orange.svg)](#22-opt-in-cloud-synthesis-srccloudsatguardianclientrs)
[![License](https://img.shields.io/badge/Edge_WAF-100%25_Free_&_Unlimited_Traffic-success.svg)](#35-pricing--licensing-zero-traffic-tax)

**SATGuardian Edge WAF** is a self-hosted Web Application Firewall
written in Rust. It evaluates security logic with **128-bit integer bitmasks
(`u128`)** in microseconds on the edge, and can — only if you turn it on — send
recorded anomalies to **SATGuardian cloud synthesis** for review. Detection quality
is **measured, not assumed**: the numbers below come from a versioned corpus and a
reproducible benchmark, one held-out batch of them included.

The product promise: **free, you get local protection; paying, you get ongoing review, update proposals and explanations — without ever giving up control of your WAF.** The local client and `satguardian-health` stay free, read-only and offline. Cloud review is opt-in (`auto_sync_enabled` defaults to `false`) and what it returns is stored as a **proposal**: nothing enters the running rule set until you approve it with `satguardian-waf clauses apply <id>` or `POST /api/waf/clauses/{id}/apply`. The messaging bot (Telegram/WhatsApp) is announced on the site, not available yet.

### 🎯 Why install SATGuardian

SATGuardian is not positioned as "another WAF". It is a **deterministic decision layer** that does what signature- and scoring-based firewalls structurally cannot:

1. **Every decision is auditable, bit by bit.** A block is a Boolean cube `(feature_vector & mask) == expected` over a 128-bit feature vector — reproducible, explainable and reviewable by an auditor without trusting a vendor's scoring internals. CRS-style engines answer "blocked, anomaly score 27"; SATGuardian answers *which structural tokens, in which combination, triggered which rule*.
2. **It complements your existing WAF instead of replacing it.** Measured head-to-head against Aegis Community v1.1.0 (Coraza + OWASP CRS 4.25.1) on 2026-11-09: on the CRS v4.30 attack suite the two engines detect **82.0% vs 80.7%**, but their coverage is strongly complementary — the union reaches **92.9% recall** while the intersection is only **69.8%**. Deployed as a cascade in front of a CRS-based WAF, SATGuardian adds detection the signatures miss; deployed alone, it adds explainability they cannot offer. Details: [§3.4](#34-first-head-to-head-vs-a-real-waf-product-aegis-community-v110).
3. **Your traffic never leaves your infrastructure.** No DNS redirection, no hosted gateway, no per-request fee. Inspection runs in your process; the only optional cloud contact is the review of recorded feature vectors — off by default, and its output arrives as proposals you approve, never as silent rule changes.
4. **Free edge, paid governance.** Edge inspection is 100% free and unlimited. The paid layer is *review*: ongoing analysis of new patterns, update proposals and explanations — metered in Security Units, with quota exhaustion pausing cloud review while local rules keep enforcing.

**Who this is for:** teams that need to *prove* why a request was blocked — regulated workloads, audit-driven security programs, and operators who want a fast deterministic first stage in front of a heavier WAF. **Who it is not for (yet):** teams that need a managed console, TLS termination, geo-blocking or rate limiting in the same box — those live in the proxy/TLS layer in front of SATGuardian.

---

## ⚡ Quick Start: Build and Test Drive

Evaluate SATGuardian Edge WAF in **Standalone Mode** with no database, broker or sidecar — the only
requirement is a Rust toolchain.

### 1️⃣ Build the standalone binary

```bash
git clone https://github.com/ExactorResearch/satguardian.git
cd satguardian
cargo build --release
```

> **Do not use the archived `dist/` and `releases/` artefacts.** They were cut on 2026-10-14/17,
> before the claim corrections and before the cloud-review approval gate existed. Those binaries
> still print the old banner text and apply cloud clauses to the running engine without asking;
> they are kept only as build history.

### 2️⃣ Launch the Standalone Reverse Proxy & Test Live Threat Detection

Spin up SATGuardian as a standalone frontline proxy and test attack blocking with `curl`:

```bash
# Terminal 0: Start any upstream app on port 3000 — e.g. a static file server:
#   python -m http.server 3000

# Terminal A: Start standalone WAF proxy on port 8080 forwarding to your application (port 3000)
# Linux/macOS: ./target/release/satguardian-waf   Windows: .\target\release\satguardian-waf.exe
./target/release/satguardian-waf proxy --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000

# Terminal B: Test a benign request (Allowed -> proxied to upstream; HTTP 200 if it serves the path, never 403)
curl -i http://localhost:8080/

# Terminal B: Test a SQLi + XSS multi-vector attack (Blocked -> HTTP 403 Forbidden)
curl -i "http://localhost:8080/api/users?search=1%27%20UNION%20SELECT%20*%20FROM%20users--%20%3Cscript%3Ealert(1)%3C/script%3E"
```

### 3️⃣ Run the Built-In Benchmark (10,000 Requests)

Measure single-core CPU throughput and in-memory bitmask evaluation latency:

```bash
# Windows
.\target\release\satguardian-waf.exe benchmark -r 10000

# Linux
./target/release/satguardian-waf benchmark -r 10000
```

*(Or skip the build step and run either command with `cargo run --release -- <subcommand>`)*

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

SATGuardian resolves this dilemma by decoupling **in-path edge inspection** from **opt-in cloud rule synthesis**.

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
│                                 (~0.46 ms p50 in-memory, native Rust)        │
│                                        /               \                   │
│                                   [ALLOW]             [BLOCK + Causal Log] │
└─────────────────────────────────────────────────────────┬──────────────────┘
                                                          │ Async SQLite
                                                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CONTROL PLANE: OPT-IN CLOUD REVIEW (Security Units - SU)                │
│                                                                            │
│  waf_ledger.db ──► SATGuardian cloud synthesis ──► Digital Twin Replay     │
│  (novel anomalies)  (runs on satguardian.tech,     (collision check on     │
│                      not in this binary)            recorded traffic)      │
│                                       │                                    │
│                                       ▼                                    │
│                          PROPOSAL in the ledger (applied = 0)              │
│                                       │  operator approves:                │
│                                       │  clauses apply / POST .../apply    │
│                                       ▼                                    │
│                     Approved clause registered in the live engine          │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Native Rust In-Path Edge Engine (`src/`)

* **Multi-Pass Lexical Normalization (`src/ast/lexer.rs`):** Applies percent-decoding, unwraps MySQL executable comments, strips inline comments, decodes HTML entities and Unicode/overlong escapes, and expands Log4j lookups before token extraction. Entity-encoded payloads are covered by `corpus/independent_v1.json`; that is a regression check, not proof of complete coverage.
* **128-Bit Feature Vector (`src/ast/features.rs`):** Packs HTTP attributes, Shannon character entropy, and structural tokens across 5 domains (`SQLi`, `XSS`, `RCE`, `LFI`, `SSRF`) into a single `u128` integer.
* **Bitmask Conjunction Evaluation (`src/engine/sat_solver.rs`):** Compares request minterms against compiled rule masks via bitwise `AND` operations (`(minterm & required_mask) == expected_bits`). On the pinned corpus at 10,000 requests the native engine measured roughly `0.46 ms` p50 and `0.94 ms` mean in-memory on this machine (re-measured 2026-11-10; an earlier run on a smaller rule set reported ~20 µs); p99 is load dependent and measured `~6 ms`.
* **Structural token conjunctions:** Rules require combinations such as `TAG_OPEN` $\land$ `SCRIPT_ELEMENT` $\land$ `DOM_EXEC` instead of single keywords. False positives are counted on the pinned corpus; the engine does not claim zero FPs.

### 2.2 Opt-in Cloud Synthesis (`src/cloud/satguardian_client.rs`)

Nothing leaves the node unless you enable it: `auto_sync_enabled` defaults to `false`. When cloud review runs (the timer worker, `satguardian-waf sync-simplify`, or `POST /api/waf/sync-simplify`), the client posts the `u128` feature vectors it recorded as novel anomalies — not raw requests, headers, bodies or client IPs — and the service answers with a minimized Boolean equation. Minimization runs on the SATGuardian service; it is not compiled into this binary and is not distributed to customers.

What the client does with that answer:

* **Validates it.** The equation is parsed into `(mask, expected)` clauses. A malformed equation, or one that yields no usable clause, is refused and the ledger is left untouched.
* **Stores it as a proposal** (`dynamic_clauses.applied = 0`). A proposal is not evaluated by the engine and is not loaded at startup.
* **Waits for your decision.** `satguardian-waf clauses list | apply <id> | reject <id>`, or `GET /api/waf/clauses/pending`, `POST /api/waf/clauses/{id}/apply`, `DELETE /api/waf/clauses/{id}` behind the admin token. Only an approved clause is registered in the live engine — an `RwLock`-guarded dynamic clause table capped at 4,096 entries, deduplicated on `(mask, bits)` — and it starts applying on the next request without restarting the process. Rejecting discards the proposal and never removes a rule already enforcing.
* **Optionally rehearses it.** `python satguardian-advisor.py` replays a candidate clause against the allowed records already present in the local ledger and reports collisions. "No collisions in the ledger" is not a false-positive rate; the held-out measurement in §3.3 is.

---

## 3. Decision: What Has Been Measured

Most of the figures below are **in-sample**: they come from payloads written in this
repository and used to drive fixes, so they track regressions rather than predict
behaviour. One batch is held out (§3.3) and it is the only accuracy number worth
quoting. The "competitor" agents are small Python regex stand-ins, not the real Coraza,
SafeLine or ModSecurity products, so no row here supports a procurement claim.

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
| Native Rust v0.3.0 | `corpus/independent_v1.json`, 10,000 requests (representative run) | p50 `~0.46 ms`, mean `~0.94 ms`, p99 `~6 ms` (re-measured 2026-11-10) | 63/63 attacks, 0/16 benign blocked |

* **Speed is in-memory only.** No TLS, proxy hop, upstream or stateful tracking
  is included. The Python reference port ran at `58.6 µs` versus `235.0 µs` for
  the CRS-style stand-in on the same stream; that compares two Python programs,
  not SATGuardian against Coraza.
* **Detection quality is a regression floor, not an estimate.** First run of the
  independent corpus scored 51/63 (80.95% recall) with 3/16 benign blocked
  (18.75% FPR). A second batch scored 11/17 (64.71%) on its first run. After the
  fixes both report 100%/0%, but every case was used to drive those fixes, so
  the result is in-sample. Details: [corpus/README.md](corpus/README.md).
* **No production evidence exists.** There is no third-party evaluation and no
  soak test. The only real-product measurement is the 2026-11-09 Aegis
  head-to-head in §3.4 — one run, one configuration, not a product ranking.
  See [STATUS.md](STATUS.md).

### 3.3 The held-out measurement (`corpus/heldout_v2.json`)

On 2026-11-04 a third batch — 98 attacks and 57 benign controls — was labelled in the
file **before the engine ran against it**, measured once, and committed
(`corpus/heldout_v2_report.json`). That is the only estimate here that is not
in-sample:

| Metric | Value | 95% Wilson CI | Basis |
| :--- | :---: | :---: | :--- |
| Recall on held-out attacks | **56.1%** | 46.3 – 65.5% | 55 of 98 detected |
| False-positive rate on held-out controls | **7.0%** | 2.8 – 16.7% | 4 of 57 blocked |

* **What works:** the families that already had rules — XSS 12/12, GraphQL 4/4,
  prototype pollution 4/4, CMS probes 5/6, path traversal 6/8.
* **What does not:** six families the engine has no category for — SSTI, NoSQL
  injection, XXE, host-header injection, HTTP response splitting and malicious
  upload — score 0 of 3 or 0 of 2 each, and SSRF detects 1 of 8.
* **The four false positives** were inline SVG/CSS with a `data:` URI, a login form
  whose values contain shell metacharacters, and two ordinary WordPress requests.
* **Limits.** Same author wrote the attacks and the controls; the controls are
  imagined traffic, not a sample from a customer's access log; the intervals are
  wide because the batch is small. The batch is now spent: tuning a rule against any
  miss listed in the report turns it into a third regression suite, and the next
  honest estimate has to come from `heldout_v3`.

**Update (2026-11-08):** later batches v3–v10 were each measured once and spent
as tuning inputs. The current publishable one-shot estimate is
`benchmarks/real_comparative/corpus/heldout_v10.jsonl`, run once before any fix
against it once: **38.6% recall / 0.0% FPR** frozen one-shot estimate (`corpus/heldout_v10_report.json`,
frozen). The v2 figure above remains for provenance; the CRS v4.30 suite is
measured in-sample at 82.0% and is not an independent evaluation. Details in
[STATUS.md](STATUS.md).

### 3.4 First head-to-head vs a real WAF product (Aegis Community v1.1.0)

On 2026-11-09 the engine was run against **Aegis Community Edition v1.1.0** —
a real, shipping WAF (Coraza engine + bundled OWASP CRS 4.25.1 LTS, paranoia
level 1, blocking mode) — over real HTTP on localhost, using the same corpus
files `satbench` consumes. This is the first comparison in this repository
against an actual product rather than a local stand-in; the run manifest and
per-case verdicts live in `benchmarks/real_comparative/results/aegis/`.

| Corpus | SATGuardian | Aegis + CRS 4.25.1 PL1 |
| :--- | :---: | :---: |
| `crs_v430.jsonl` (4,050 vendor-authored attacks) | **82.0% recall** (3,321) | **80.7% recall** (3,268) |
| `heldout_v10.jsonl` (70 attacks) | 100% — post-tuning diagnostic; frozen one-shot **38.6%** | **68.6% recall** (48/70) |
| `heldout_v10.jsonl` (44 benign controls) | 0.0% FPR — post-tuning diagnostic; frozen one-shot **0.0%** | **36.4% FPR** (16/44 blocked) |
| `benign_heldout_v3_v10.jsonl` (665 pooled benign controls) | **0.5% FPR** (3/665; v10-only non-spent subset 0/44) | **22.9% FPR** (152/665 blocked) |

* **Parity on the vendor suite.** On the OWASP CRS v4.30 attack suite — the
  rule set's own tests — SATGuardian detects slightly more than the real CRS
  engine does (82.0% vs 80.7%). The difference is within noise; what matters
  is that a ~20-rule bitmask engine is in the same band as hundreds of CRS
  signatures.
* **Coverage is complementary, not competitive.** Per-case verdicts show the
  union of both engines reaches **92.9% recall** on `crs_v430` while their
  intersection is only **69.8%**. Each engine catches whole rule families the
  other misses (e.g. SATGuardian 44/44 vs Aegis 7/44 on CRS rule 934140;
  Aegis 210/330 vs SATGuardian 162/330 on rule 944300). A cascade or ensemble
  is the natural architecture, and it is a product story CRS-only vendors
  cannot copy.
* **Aegis's false positives are real and repeatable.** On the 44 v10
  controls Aegis blocked 16 (36.4%); pooled across all 665 benign controls
  from batches v3–v10 it blocked 152 (**22.9% FPR**, 95% CI 19.8–26.2%),
  consistently in every batch — ordinary OData `$filter` queries, JSON POST
  bodies, IMAP-like protocol text and WordPress-style requests. SATGuardian
  blocked 3 of the same 665 (0.5%, CI 0.2–1.3%); only the 44 v10 controls are
  non-spent for SATGuardian (v3–v9 benign controls were tuning inputs), where
  it blocked 0 — classic CRS PL1 behaviour on non-HTML APIs, measured.
* **Limits of this run.** Aegis ran CRS 4.25.1 (not 4.30), paranoia level 1
  only, community edition, plain HTTP, localhost, dummy upstream, and its
  default rate limiter was disabled for isolation. `latency_us` columns are
  not comparable: Aegis numbers are full HTTP round-trips including the
  upstream hop; SATGuardian numbers are in-process rule evaluation. See
  `benchmarks/real_comparative/results/aegis/RUN.json` for the full manifest.

### 3.5 100% On-Premise Traffic Sovereignty

SATGuardian runs **entirely inside your infrastructure**. We **never** host customer
traffic, and no request is forwarded to us: inspection happens in the local process.
The only thing that can leave the node is the optional cloud review of §2.2, which
sends recorded `u128` feature vectors, is disabled by default, and never changes the
rule set by itself. No DNS or CNAME redirection is required:

1. **Kubernetes / Envoy Proxy Native Sidecar:** Runs alongside Envoy via `ext_authz` over an in-memory Unix Domain Socket (`unix:///run/satguardian/waf.sock`), adding the engine's measured in-memory cost (hundreds of microseconds) with no network hop.
2. **Reverse Proxy:** Frontline protection for Nginx, Apache, or Microsoft IIS (including Windows Service deployment via `install.ps1`).
3. **Standalone Binary:** Self-contained Rust binary built with `cargo build --release` (`satguardian-waf proxy --listen 127.0.0.1:8080`). It speaks plain HTTP; terminate TLS in a reverse proxy or Envoy in front of it.

### 3.6 Pricing & Licensing: Zero Traffic Tax

The paid product is the narrative in one line: ongoing review, update proposals and
explanations, with you approving every change. On 2026-11-03 the owner approved
packaging the plans by **servers covered and new rule patterns reviewed each month**,
published on the site at the existing prices, with SU kept as internal accounting.
The monthly pattern allowance (Scout 5,000 · Pro 25,000 · Startup 125,000 · Scale
500,000) is enforced in the service source since 2026-11-04 and **not yet on the
running host**: on the live service today the limit that actually bites is the SU
pool.

| Plan | Monthly Price | Servers covered | New rule patterns reviewed / mo | SU pool (internal) | Job ceiling | Certificate |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **Community** | **$0** | 1 | — | 5 SU / mo | 12 vars / 200 minterms | No |
| **SCOUT** | **$20 USD** | 1 | 5,000 | 1,000 SU / mo | 20 vars / 2,500 minterms | Yes |
| **PRO** | **$49 USD** | 5 | 25,000 | 5,000 SU / mo | 64 vars / 10,000 minterms | Yes |
| **STARTUP** | **$499 USD** | 10 | 125,000 | 50,000 SU / mo | 128 vars / 100,000 minterms | Yes |
| **ESCALA (Scale)** | **$2,499 USD** | 30 | 500,000 | 500,000 SU / mo | 128 vars / 1,000,000 minterms | Yes |
| **EMPRESARIAL** | **Custom** | Above 30 | Negotiated | Negotiated annual pool | Negotiated in writing | Yes |

Prices, server counts and pattern allowances are the ones published on
[pricing.html](https://satguardian.tech/pricing.html); `plans.js` in the service
repository mirrors them and is what the backend enforces. There are no automatic
overage charges: extra SU is requested manually from the Token Manager and is
approved by hand. Community gets one cloud compression per rolling 30 days and no
certificate.

> **Quota behavior:** The local Edge WAF is **100% free and unlimited** ($0.00/request). You pay only for cloud synthesis, metered in **Security Units (SU)**. If the monthly allowance is exhausted (`HTTP 402`), cloud synthesis pauses and the local Edge WAF keeps serving traffic with the last rule matrix you approved. *(256+ variable matrices are handled as individual engineering projects, not as a plan.)*

---

## 4. Action: Getting Started in Six Steps

Follow this step-by-step onboarding journey to evaluate SATGuardian in your environment:

### Step 1: Build and run the benchmark

Run the benchmark on your machine across 10,000 HTTP requests:

```powershell
# From a git clone, after `cargo build --release`
.\target\release\satguardian-waf.exe benchmark -r 10000

# Or in one step, straight from source
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
./target/release/satguardian-waf proxy --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000

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

### Step 4: Turn on cloud review and decide what reaches the WAF

This is the paid loop in practice, and it is opt-in at both ends: the node only uploads
if `auto_sync_enabled = true`, and what comes back is a proposal, not a change.

```bash
# 1. Ask for a review of the anomalies recorded so far (nothing is applied here)
satguardian-waf sync-simplify --limit 100

# 2. Read what arrived
satguardian-waf clauses list
curl -H "Authorization: Bearer $SATGUARDIAN_ADMIN_TOKEN" \
  http://127.0.0.1:10001/api/waf/clauses/pending

# 3. Approve or discard, one at a time
satguardian-waf clauses apply <clause-id>
satguardian-waf clauses reject <clause-id>
```

A proposal that is never approved has no effect: the engine keeps enforcing the last
matrix you accepted. While the proxy is running, approving through
`POST /api/waf/clauses/{id}/apply` also hot-swaps the clause into the live engine;
approving from the CLI takes effect the next time it starts.

### Step 5: Generate Forensic Audit Reports

Analyze recorded transactions in `waf_ledger.db`, replay candidate clauses against the
allowed records already in the ledger, and generate evidence-backed HTML/Markdown audit
reports. They are forensic reports about your own traffic, not a compliance attestation:

```powershell
python satguardian-advisor.py --report audit_report.html
python satguardian-advisor.py --report-md audit_report.md
```

### Step 6: Check the rule set without the cloud

`satguardian-health` reads `waf_config.toml` and `waf_ledger.db` in place and reports rule
inventory, duplicate or contradictory rules, observed traffic and rules that never matched.
It never opens a network socket, never uploads anything and has no telemetry; the ledger is
opened read-only (`mode=ro`). This is part of the free Edge binary, not a cloud feature.

```bash
satguardian-health
satguardian-health --json
satguardian-health --strict   # exit 1 if a WARN finding is present, useful in cron
```

A rule that never matched in a given ledger is reported as a prompt to check it, not as proof
that it is dead: the sample may not contain a request that rule governs.

* **Full Operations & Configuration Guide:** Read the [Official Documentation](https://exactorresearch.github.io/satguardian/) for detailed configuration, customization, and tool usage.
* **Watch it live in a terminal:** `python satguardian-top.py` reads the same ledger the proxy writes.
* **Talk to us:** the audit and design-partner offer is at [satguardian.tech](https://satguardian.tech); issues go to GitHub.

---

*© 2026 SATGuardian. Edge WAF released under Apache-2.0; detection improvements come from the cloud service, which is not part of this binary.*
