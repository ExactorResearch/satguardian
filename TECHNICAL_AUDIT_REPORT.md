# Technical Audit & Empirical Verification Report: `satguardian` (SATGuardian Edge WAF)

**Audit Scope:** Code review of `src/` (Rust), `satguardian_waf/` (Python) and the bundled SQLite ledger  
**Target Version:** `v0.3.0`  
**Audit Objective:** Check implementation claims against source, and report only measurements that can be reproduced from the repository.

> **Status: research prototype, not a production-ready WAF.** Earlier revisions of
> this report capped accuracy at `99.9%`, floored error rates at `< 0.1%`, and
> labelled Python stand-ins as vendor products. Those claims were fabricated or
> misleading and have been removed. See [STATUS.md](STATUS.md).

---

## 1. Executive Summary: What Is Implemented vs. Theoretical Research

A line-by-line review of the `satguardian` repository and adjacent workspace projects (`hesize-code-ia`, `adn`, `guardian-api-`, `optimizador_bayesiano`, `f32`) distinguishes **implemented code** from **external research concepts**:

| Technical Concept | Status in `satguardian` | Actual Code Implementation & Location |
| :--- | :---: | :--- |
| **Multi-Pass Lexical Normalization & Tokenization** | **✅ Implemented** | `src/ast/lexer.rs` (`Lexer::normalize_and_tokenize`) and `satguardian_waf/core/solver_sat.py` unwind nested URL/HTML encodings, strip `/*...*/` comments, and extract structural tokens across 5 attack domains (`SQLi`, `XSS`, `RCE`, `LFI`, `SSRF`). |
| **128-Bit Feature Vector (`u128`)** | **✅ Implemented** | `src/ast/features.rs` (`FeatureVector(pub u128)`) packs HTTP metadata, Shannon entropy flags, and lexical token presence into a 128-bit integer. |
| **Bitmask Conjunction Evaluator ("SAT Engine")** | **✅ Implemented** | `src/engine/sat_solver.rs` (`SatEngine`) evaluates pre-compiled boolean cubes in $O(1)$ per rule via bitwise `AND`: `(minterm & required_mask) == expected_bits`. *(Note: It is a fast bitmask evaluator, not an in-path backtracking DPLL/CDCL SAT solver).* |
| **Out-of-Band EXACTOR GXOR Minimization** | **✅ Implemented** | `src/cloud/satguardian_client.rs` (`SatguardianCloudClient::simplify`) and `exactor-core-v128` (`procesar_gxor`, `modify_gray_code`) simplify up to **128 Boolean variables (`u128` minterms)** out of band using the **`{AND, OR, NOT, XOR}`** operator basis and Differential Gray Code Mapping in $O(\text{term\_count})$ linear time. |
| **Digital Twin Benign Traffic Replay** | **✅ Implemented** | `satguardian-advisor.py` (`SimulationAgent`) replays candidate rules against benign requests recorded in `waf_ledger.db` and reports collisions. It does not certify a fixed false-positive rate. |
| **Lock-Free Atomic Rule Hot-Reload** | **✅ Implemented** | `src/proxy/http_proxy.rs` uses `arc_swap::ArcSwap` to swap rule matrices in memory without dropping TCP connections. |
| **Token-Bucket Burst Rate Limiting** | **✅ Implemented** | `src/engine/sat_solver.rs` uses lock-free `DashMap` counters per client IP to block Layer-7 burst floods (`SAT-STATE-01`). |
| **Wolfram Cellular Automata / M-Code / Graph Isomorphism** | **❌ Not in WAF Code** | Part of separate theoretical research projects (`hesize-code-ia`, `adn`); removed from all WAF documentation to maintain strict engineering accuracy. |

---

## 2. Reproducible Measurements

No value is capped or floored. The benchmark refuses to run without the pinned
corpus, and prints its scope on every run.

### 2.1 Detection on the pinned corpus

| Corpus | First run before fixes | Current regression | Nature of the number |
| :--- | :---: | :---: | :--- |
| `corpus/independent_v1.json` (63 attacks, 16 benign) | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) | 63/63, 0/16 blocked | In-sample regression |
| `corpus/heldout_v1.json` (17 attacks, 4 benign) | 11/17 recall (64.71%), 0/4 benign blocked | 17/17, 0/4 blocked | Consumed held-out batch |

Both corpora were used to drive fixes after their first run. The current 100%/0%
therefore means "the pinned cases still pass", not "the engine catches X% of
real attacks". Protocol: [corpus/README.md](corpus/README.md).

### 2.2 In-memory latency

`satguardian-waf benchmark -r 10000` on the same corpus, one representative run:

- **Total requests:** `10,000` (corpus cycled)
- **Single-thread throughput:** `44,492 req/sec`
- **Min:** `11.9 µs`
- **p50:** `19.8 µs`
- **Mean:** `21.6 µs`
- **p90:** `29.1 µs`
- **p99:** `49.3 µs` (near the `50 µs` target; varies with load)
- **Max:** `311.1 µs`

Scope: in-memory rule evaluation only. No TLS, proxy hop, upstream service or
stateful tracking is included.

### 2.3 Python stand-in harness

`python run_benchmark.py 1000` compares the Python reference port against local
Python stand-ins. It does not execute Coraza, SafeLine, ModSecurity or an LLM.
The report prints the dataset provenance and a disclaimer next to the metrics.

---

## 3. Bundled Ledger Walkthrough (`waf_ledger.db`)

Running `python satguardian-advisor.py --report-md audit_report.md` against the
bundled ledger produces a demo audit:
- **Total recorded requests:** `3,799`
- **Blocked:** `2,136` (`951` SQLi, `477` XSS, `472` path traversal, `234` rate-limit bursts, `2` SSRF)
- **Allowed benign:** `1,663`
- **Replay:** candidate rules are replayed against the benign rows; collisions are reported per run. No fixed false-positive floor is claimed.

The ledger is demo data for exercising the advisor pipeline, not independently
labelled ground truth and not a customer tenant.

