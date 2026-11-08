# Structured Grammar Inspection & Offline Rule Synthesis

**Architectural Overview: In-Path Bitmask Evaluation plus Opt-In Cloud Rule Review**  
**Codebase Reference:** `src/engine/sat_solver.rs`, `src/cloud/satguardian_client.rs`, `src/ledger/sqlite_ledger.rs`, `src/api/server.rs`, `satguardian-advisor.py`

> **Status: research prototype.** Detection numbers in this document are
> in-sample results on a hand-written corpus plus one held-out run of the same
> author's payloads, and comparisons against local Python stand-ins. They are
> not vendor benchmarks and do not establish production readiness. There is no
> third-party evaluation. See [STATUS.md](STATUS.md).

---

## 1. Core Engineering Problem

Web application firewalls face an operational trade-off between **latency**, **evasion resilience**, and **false positive rates**:

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

SATGuardian resolves this trade-off by decoupling **real-time edge inspection** from **out-of-band rule review**, and by keeping the second plane behind an explicit operator decision:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. HOT PATH: SELF-HOSTED EDGE WAF                                          │
│    On your own node, no per-request fee, enforces with no network call     │
│                                                                            │
│ HTTP Request ──► Multi-Pass Lexer ──► 128-Bit FeatureVector (u128)         │
│    (src/ast/lexer.rs)        (src/ast/features.rs)                         │
│                  │                                                         │
│                  ▼                                                         │
│    Bitwise Rule Mask Evaluation (src/engine/sat_solver.rs)                 │
│    (minterm & required_mask) == expected_bits                              │
│    ~20 µs avg in-memory, native Rust; TLS and proxy hops excluded          │
│           /                        \                                       │
│    [ALLOW: forward to upstream]   [BLOCK 403 + causal log]                 │
└────────────────────────────────────────┬───────────────────────────────────┘
                                         │  Async SQLite ledger (waf_ledger.db)
                                         ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ 2. CONTROL PLANE: OPT-IN CLOUD REVIEW → PROPOSALS → APPROVAL               │
│                                                                            │
│ waf_ledger.db ──► cloud review client ──► SATGuardian cloud synthesis      │
│   (ledger)      (satguardian_client.rs)   (satguardian.tech, off-repo)     │
│                                                                            │
│ Returned clauses are stored as PROPOSALS: dynamic_clauses.applied = 0      │
│ They are not registered in the engine and are not loaded at startup.       │
│ The advisor replays candidates against benign rows, reports collisions.    │
│      │                                                                     │
│      ▼                                                                     │
│ clauses apply | clauses reject  /  POST /api/waf/clauses/{id}/apply        │
│      │ approved only, behind the admin token                               │
│      ▼                                                                     │
│ Clause registers in the engine; new requests see it, no restart.           │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Plane 1: In-Path Lexical & Bitmask Engine (`src/engine/sat_solver.rs`)
- **Multi-Pass Canonicalization:** Decodes nested URL encodings, strips inline comments (`/**/`), and extracts structural grammar tokens across five domains (`ISLAND-SQLI`, `ISLAND-XSS`, `ISLAND-RCE`, `ISLAND-LFI`, `ISLAND-SSRF`).
- **Bitwise Conjunction Evaluation:** Evaluates compiled rules via `u128` bitwise masks. Rules require structural conjunctions rather than isolated keywords. On the 16 benign controls in `corpus/independent_v1.json` the engine produced no false positives; that is an in-sample regression floor on a sample too small to generalize, and the one held-out batch measured a 7.0% false-positive rate on 57 controls.

### 2.2 Plane 2: Out-of-Band Cloud Review, Replay and Approval (`src/cloud/satguardian_client.rs`, `src/ledger/sqlite_ledger.rs`, `satguardian-advisor.py`)
- **Minterm Harvesting:** Requests that match no compiled cube are logged asynchronously to SQLite — without slowing down the hot path — as patterns awaiting analysis. They are candidates for review, not unprotected threats or gaps in coverage.
- **Opt-in Upload, Off by Default:** Nothing is sent anywhere unless `auto_sync_enabled` is turned on (`false` by default in `src/config.rs` and `waf_config.toml`), the operator runs `satguardian-waf sync-simplify`, or a token-authenticated `POST /api/waf/sync-simplify` hits the local API.
- **Cloud Synthesis Is a Service, Not a Component of This Repository:** The client posts its variable catalogue and minterms to `https://satguardian.tech/api/simplify`; the Boolean minimization over the `{AND, OR, NOT, XOR}` basis runs there. The minimizer is server-side, is not distributed to customers, and its internal algorithm and reduction cost are not characterized in this codebase. The client only compiles the returned equation into `(required_mask, expected_bits)` clauses (`compile_equation_to_clauses()`) and evaluates them.
- **Results Arrive as Proposals:** Each compiled clause is written to `dynamic_clauses` with `applied = 0`. Proposals are never registered in the running engine and are skipped at startup, which loads approved clauses only (`load_applied_clauses()`).
- **Digital-Twin Replay (`SimulationAgent`):** The advisor replays its own candidates against the benign requests recorded in `waf_ledger.db` and reports collisions, so the operator sees the evidence before deciding. Collision counts depend on the ledger contents and are not a fixed guarantee.
- **Approval Is the Only Thing That Enforces:** `satguardian-waf clauses apply <id>` (from the next start) or `POST /api/waf/clauses/{id}/apply` on a running process registers one clause in the engine; `reject` deletes only a proposal and never removes a rule already in force.

---

## 3. Measurement Summary

| Measurement | Source | Result |
| :--- | :--- | :--- |
| Detection on pinned corpus | `corpus/independent_v1.json`, 63 attacks + 16 benign | 63/63 detected, 0/16 benign blocked — **in-sample regression floor**, not a quality estimate |
| First-run baseline before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Second batch, first run | `corpus/heldout_v1.json`, 17 attacks + 4 benign | 11/17 recall (64.71%), 0/4 benign blocked; batch consumed by the fix pass, so its 17/17 rerun is in-sample |
| **Held-out estimate (current)** | `benchmarks/real_comparative/corpus/heldout_v10.jsonl`, run once on 2026-11-08: 70 attacks + 44 controls | **38.6% recall** (27/70, 95% CI 28.0–50.3%) and **0.0% false-positive rate** (0/44, 95% CI 0.0–8.0%); earlier `heldout_v2` 56.1%/7.0% kept for provenance |
| In-memory latency, native Rust | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load; in-memory only, excluding TLS, the proxy hop and the upstream |
| Python reference + stand-ins | `run_benchmark.py 1000` | Reported by the harness with provenance; not a vendor comparison |

No accuracy value is capped and no error rate is floored. Earlier versions of
this table did both (`99.9%` cap, `< 0.1%` floor); those numbers were fabricated
and have been removed.

There is **no third-party or independent evaluation**. Every corpus, including
the held-out batch, was written inside this project from public payload
catalogues and labelled by the same side that owns the engine, so the 38.6% /
0.0% figures (and the earlier 56.1% / 7.0%) describe those payloads and nothing else.

---

## 4. Commercial & Operational Continuity Model

The model in one sentence: **free, you get local protection on your own node;
paying, you get continuous review of new patterns, update proposals and
explanations — without ever giving up control of your WAF.**

1. **Self-Hosted Traffic, by Default Offline:** The Edge WAF runs entirely on your own infrastructure (standalone binary, reverse proxy in front of Nginx/Apache/IIS, or an Envoy sidecar in Kubernetes). There is no DNS CNAME redirection through external bastions, and with the default configuration the node makes no outbound call at all: `auto_sync_enabled` is `false`.
2. **Edge Inspection Carries No Per-Request Fee:** In-path request inspection is free and unlimited; the engine's rule set is local, so it keeps enforcing with no network.
3. **Paid Cloud Review, Metered in Security Units (SU):** A paid plan covers the SATGuardian cloud synthesis service — reviewing the patterns your node recorded and sending back update proposals with the equation and reduction they came from. SU accounting is based on the variables and minterms the service compresses. If the monthly SU quota is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud review pauses while the local Edge WAF keeps enforcing the rules you already approved.
4. **Control Stays With the Operator:** Cloud results are proposals stored in your own ledger. They enforce only after you approve them, one at a time, with `satguardian-waf clauses apply <id>` or the admin-token API. Rejecting a proposal cannot remove protection that is already in force, and turning the cloud off entirely leaves a fully functioning local WAF.
