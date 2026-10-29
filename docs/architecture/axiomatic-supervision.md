# Structured Grammar Inspection & Offline Rule Synthesis

**Architectural Overview: In-Path Bitmask Evaluation and Out-of-Band EXACTOR GXOR (`{AND, OR, NOT, XOR}`) Minimization up to 128 Variables**  
**Codebase Reference:** `src/engine/sat_solver.rs`, `src/cloud/satguardian_client.rs`, `exactor-core-v128`, `satguardian-advisor.py`

---

## 1. Core Engineering Problem

Enterprise Web Application Firewalls face an operational trade-off between **latency**, **evasion resilience**, and **false positive rates**:

1. **Unnormalized Signature WAFs (Classical ModSecurity Regex):** Fast on simple strings (`0.0427 ms` avg in our Python benchmark), but easily bypassed by inline comments, URL encoding, or alternative DOM vectors (`47.0%` False Negative Rate).
2. **Multi-Target Anomaly Scoring WAFs (OWASP CRS v4 / Coraza):** Comprehensive coverage (`97.3%` accuracy at Paranoia Level 1), but must run multiple transformation passes and evaluate dozens of regular expressions per request (`0.2178 ms` avg — `3.38x` slower than SATGuardian in Python and `15.0x` slower than SATGuardian's `0.0145 ms` native Rust engine). Raising CRS Paranoia Levels to catch triple-encoded payloads increases false positives on benign traffic.
3. **Probabilistic Token / NLP Classifiers:** Vulnerable to false positives whenever legitimate users submit technical text containing SQL, HTML, or shell terminology (`24.6%` False Positive Rate in empirical testing).

---

## 2. The Two-Plane SATGuardian Architecture

SATGuardian resolves this trade-off by decoupling **real-time edge inspection** from **offline boolean rule synthesis**:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. HOT PATH: SOVEREIGN EDGE WAF (100% On-Premise, Unlimited Traffic)       │
│                                                                            │
│  HTTP Request ──► Multi-Pass Lexer ──► 128-Bit FeatureVector (u128)        │
│                   (src/ast/lexer.rs)   (src/ast/features.rs)               │
│                                                 │                          │
│                                                 ▼                          │
│                                 Bitwise Rule Mask Evaluation               │
│                                 (minterm & mask) == expected               │
│                                 (14.53 µs avg in Native Rust)              │
│                                        /               \                   │
│                                   [ALLOW]             [BLOCK + Causal Log] │
└─────────────────────────────────────────────────────────┬──────────────────┘
                                                          │ Async SQLite
                                                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CONTROL PLANE: OFFLINE ADVISOR & CLOUD SYNTHESIS (Security Units - SU) │
│                                                                            │
│  waf_ledger.db ──► EXACTOR GXOR (AND, OR, NOT, XOR)    ──► Digital Twin    │
│  (3,799 logs)      128-Variable Boolean Minimization       Replay (<0.1% FP│
│                    (satguardian_client.rs / exactor-core)        │         │
│                                                                  ▼         │
│                                                   Atomic ArcSwap Hot-Reload│
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Plane 1: In-Path Lexical & Bitmask Engine (`src/engine/sat_solver.rs`)
- **Single-Pass Canonicalization:** Decodes nested URL encodings, strips inline comments (`/**/`), and extracts structural grammar tokens across five domains (`ISLAND-SQLI`, `ISLAND-XSS`, `ISLAND-RCE`, `ISLAND-LFI`, `ISLAND-SSRF`).
- **Bitwise Conjunction Evaluation:** Evaluates compiled rules via `u128` bitwise masks. Because rules require structural conjunctions rather than isolated keywords, benign technical prose passes cleanly (`< 0.1%` FPR).

### 2.2 Plane 2: Out-of-Band EXACTOR GXOR Synthesis & Digital Twin (`src/cloud/satguardian_client.rs`, `exactor-core-v128`, `satguardian-advisor.py`)
- **Minterm Harvesting:** Novel high-entropy anomalies (`14` pending `u128` minterms in the current `waf_ledger.db`) and hostile IP/route patterns are logged asynchronously to SQLite without slowing down the hot path.
- **EXACTOR GXOR Boolean Minimization (Up to 128 Variables):** Unlike classical Quine-McCluskey or Espresso algorithms—which are restricted to `{AND, OR, NOT}` and suffer from $O(2^n)$ exponential blow-up beyond 20–30 variables—the **EXACTOR GXOR** engine (`procesar_gxor` in `exactor-core-v128`) operates over the complete **`{AND, OR, NOT, XOR}`** ($\{\land, \lor, \neg, \oplus\}$) basis using **Differential Gray Code Mapping** (`modify_gray_code`). By locating logical neighbors in $O(1)$ via Gray Code lookups and collapsing symmetric/parity patterns into native `XOR`/`NXOR` operations, GXOR scales linearly $O(\text{term\_count})$ across all **128 variables (`u128`)**, reducing gate counts by up to 80%.
- **Digital Twin Replay (`SimulationAgent`):** Every candidate rule is replayed against all historical benign requests (`1,663` benign records in `waf_ledger.db`). Only rules verified to produce `< 0.1%` false positives on historical benign traffic are approved for hot-reload.

---

## 3. Empirical Validation Summary

| Benchmark Suite | Dataset Size | Measured Latency | Detection Accuracy (Capped) | False Positive Rate (Floored) |
| :--- | :---: | :---: | :---: | :---: |
| **Native Rust Edge Engine (`satguardian-waf-v0.2.0.exe`)** | `10,000` reqs | `13.60 µs` (`p50`) / `14.53 µs` (`avg`) / `30.50 µs` (`p99`) | **99.9%** | **< 0.1%** (`0.1%`) |
| **Python Reference Engine (`run_benchmark.py 1000`)** | `1,000` reqs | `64.40 µs` (`0.0644 ms` avg) / `188.20 µs` (`p99`) | **99.9%** | **< 0.1%** (`0.1%`) |
| **Forensic Production Ledger (`waf_ledger.db`)** | `3,799` reqs | `856.7 µs` (`p50` incl. SQLite telemetry) | `2,136` blocked / `1,663` allowed | **< 0.1%** verified via Digital Twin |

---

## 4. Commercial & Operational Continuity Model

1. **100% On-Premise Traffic Sovereignty:** The Edge WAF runs entirely inside the customer's infrastructure (Standalone binary, Reverse Proxy in front of Nginx/Apache/IIS, or Kubernetes Envoy Sidecar). Customer traffic is never routed through external DNS CNAME bastions.
2. **Unlimited Edge Inspection at $0.00/Request:** In-path request inspection is 100% free and unlimited.
3. **Security Units (SU) for Cloud GXOR Rule Optimization:** Cloud-assisted **EXACTOR GXOR** boolean synthesis is metered in **Security Units (SU)** based on the number of variables (up to 128 in SaaS tiers) and minterms compressed. If an organization's monthly SU quota is exhausted (HTTP 402 `SU_QUOTA_EXHAUSTED`), cloud optimization pauses while the local Edge WAF continues protecting traffic uninterrupted with its last compiled bitmask matrix.
