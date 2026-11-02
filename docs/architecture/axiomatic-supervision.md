# Structured Grammar Inspection & Offline Rule Synthesis

**Architectural Overview: In-Path Bitmask Evaluation and Out-of-Band EXACTOR GXOR (`{AND, OR, NOT, XOR}`) Minimization up to 128 Variables**  
**Codebase Reference:** `src/engine/sat_solver.rs`, `src/cloud/satguardian_client.rs`, `exactor-core-v128`, `satguardian-advisor.py`

> **Status: research prototype.** Detection numbers in this document are
> in-sample results on a hand-written corpus and comparisons against local
> Python stand-ins. They are not vendor benchmarks and do not establish
> production readiness. See [STATUS.md](../status.md).

---

## 1. Core Engineering Problem

Enterprise Web Application Firewalls face an operational trade-off between **latency**, **evasion resilience**, and **false positive rates**:

1. **Unnormalized Signature WAFs:** fast on simple strings but bypassable by
   inline comments, URL encoding or alternative DOM vectors. The local
   unnormalized-regex stand-in misses `47.0%` of attacks on the in-repo stream;
   that is a property of the stand-in, not a measurement of ModSecurity.
2. **Multi-Target Anomaly Scoring WAFs (OWASP CRS / Coraza):** broader coverage
   requires transformation passes and dozens of rule evaluations per request.
   The local CRS-style stand-in costs `0.2350 ms` average in Python and misses
   `5.4%` on the same stream. No claim is made about the real engine, whose rule
   count, paranoia level and tuning differ substantially.
3. **Probabilistic Token / NLP Classifiers:** fixed token weights can fire on
   legitimate technical prose. The local hand-written heuristic scores a `24.6%`
   false-positive rate on the in-repo benign controls; it is not a trained model.

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
│                                 (~20 µs avg in-memory, native Rust)        │
│                                        /               \                   │
│                                   [ALLOW]             [BLOCK + Causal Log] │
└─────────────────────────────────────────────────────────┬──────────────────┘
                                                          │ Async SQLite
                                                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CONTROL PLANE: OFFLINE ADVISOR & CLOUD SYNTHESIS (Security Units - SU) │
│                                                                            │
│  waf_ledger.db ──► EXACTOR GXOR (AND, OR, NOT, XOR)    ──► Digital Twin    │
│  (ledger)          128-Variable Boolean Minimization       Replay (collisions)│
│                    (satguardian_client.rs / exactor-core)        │         │
│                                                                  ▼         │
│                                                   Atomic ArcSwap Hot-Reload│
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Plane 1: In-Path Lexical & Bitmask Engine (`src/engine/sat_solver.rs`)
- **Single-Pass Canonicalization:** Decodes nested URL encodings, strips inline comments (`/**/`), and extracts structural grammar tokens across five domains (`ISLAND-SQLI`, `ISLAND-XSS`, `ISLAND-RCE`, `ISLAND-LFI`, `ISLAND-SSRF`).
- **Bitwise Conjunction Evaluation:** Evaluates compiled rules via `u128` bitwise masks. Rules require structural conjunctions rather than isolated keywords. On the 16 benign controls in `corpus/independent_v1.json` the engine produced no false positives; that sample is too small to generalize.

### 2.2 Plane 2: Out-of-Band EXACTOR GXOR Synthesis & Digital Twin (`src/cloud/satguardian_client.rs`, `exactor-core-v128`, `satguardian-advisor.py`)
- **Minterm Harvesting:** Novel high-entropy anomalies (`14` pending `u128` minterms in the current `waf_ledger.db`) and hostile IP/route patterns are logged asynchronously to SQLite without slowing down the hot path.
- **EXACTOR GXOR Boolean Minimization (Up to 128 Variables):** Unlike classical Quine-McCluskey or Espresso algorithms—which are restricted to `{AND, OR, NOT}` and suffer from $O(2^n)$ exponential blow-up beyond 20–30 variables—the **EXACTOR GXOR** engine (`procesar_gxor` in `exactor-core-v128`) operates over the complete **`{AND, OR, NOT, XOR}`** ($\{\land, \lor, \neg, \oplus\}$) basis using **Differential Gray Code Mapping** (`modify_gray_code`). By locating logical neighbors via Gray Code lookups and collapsing symmetric/parity patterns into native `XOR`/`NXOR` operations, GXOR is designed to scale as $O(\text{term\_count})$ across all **128 variables (`u128`)**. The size reduction versus a naive Sum-of-Products expansion is not measured in this repository.
- **Digital Twin Replay (`SimulationAgent`):** Every candidate rule is replayed against the benign requests recorded in `waf_ledger.db`. Rules that collide with known-good traffic are rejected. The collision counts depend on the ledger contents and are not a fixed guarantee.

---

## 3. Measurement Summary

| Measurement | Source | Result |
| :--- | :--- | :--- |
| Detection on pinned corpus | `corpus/independent_v1.json`, 63 attacks + 16 benign | 63/63 detected, 0/16 benign blocked (in-sample regression) |
| First-run baseline before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Held-out first run | `corpus/heldout_v1.json`, 17 attacks + 4 benign | 11/17 recall (64.71%), 0/4 benign blocked; now consumed |
| In-memory latency, native Rust | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load |
| Python reference + stand-ins | `run_benchmark.py 1000` | Reported by the harness with provenance; not a vendor comparison |

No accuracy value is capped and no error rate is floored. Earlier versions of
this table did both (`99.9%` cap, `< 0.1%` floor); those numbers were fabricated
and have been removed.

---

## 4. Commercial & Operational Continuity Model

1. **100% On-Premise Traffic Sovereignty:** The Edge WAF runs entirely inside the customer's infrastructure (Standalone binary, Reverse Proxy in front of Nginx/Apache/IIS, or Kubernetes Envoy Sidecar). Customer traffic is never routed through external DNS CNAME bastions.
2. **Unlimited Edge Inspection at $0.00/Request:** In-path request inspection is 100% free and unlimited.
3. **Security Units (SU) for Cloud GXOR Rule Optimization:** Cloud-assisted **EXACTOR GXOR** boolean synthesis is metered in **Security Units (SU)** based on the number of variables (up to 128 in SaaS tiers) and minterms compressed. If an organization's monthly SU quota is exhausted (HTTP 402 `SU_QUOTA_EXHAUSTED`), cloud optimization pauses while the local Edge WAF continues protecting traffic uninterrupted with its last compiled bitmask matrix.
