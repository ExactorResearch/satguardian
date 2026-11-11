# Technical Audit & Empirical Verification Report: `satguardian` (SATGuardian Edge WAF)

**Audit Scope:** Code review of `src/` (Rust), `satguardian_waf/` (Python) and the bundled SQLite ledger  
**Target Version:** `v0.3.0`  
**Audit Objective:** Check implementation claims against source, and report only measurements that can be reproduced from the repository.

> **Status: SATGuardian Edge WAF v0.3.0.** Earlier revisions of
> this report capped accuracy at `99.9%`, floored error rates at `< 0.1%`, and
> labelled Python stand-ins as vendor products. Those claims were fabricated or
> misleading and have been removed. See [STATUS.md](STATUS.md).

---

## 1. Executive Summary: What Is Implemented vs. Theoretical Research

A line-by-line review of the `satguardian` repository and adjacent workspace projects (`hesize-code-ia`, `adn`, `guardian-api-`, `optimizador_bayesiano`, `f32`) distinguishes **implemented code** from **external research concepts**:

| Technical Concept | Status in `satguardian` | Actual Code Implementation & Location |
| :--- | :---: | :--- |
| **Multi-Pass Lexical Normalization & Tokenization** | **✅ Implemented** | `src/ast/lexer.rs` (`AstLexer`) and `satguardian_waf/core/solver_sat.py` unwind nested URL/HTML encodings, strip `/*...*/` comments, and extract structural tokens across 5 attack domains (`SQLi`, `XSS`, `RCE`, `LFI`, `SSRF`). |
| **128-Bit Feature Vector (`u128`)** | **✅ Implemented** | `src/ast/features.rs` (`FeatureVector { bits: u128 }`, 40 named variables in the current catalogue) packs HTTP metadata, Shannon entropy flags, and lexical token presence into a 128-bit integer. |
| **Bitmask Conjunction Evaluator ("SAT Engine")** | **✅ Implemented** | `src/engine/sat_solver.rs` (`SatguardianSatEngine`) evaluates pre-compiled boolean cubes per rule via bitwise `AND`: `(fv.bits & required_mask) == expected_bits`. *(Note: It is a fast bitmask evaluator, not an in-path backtracking DPLL/CDCL SAT solver).* |
| **Opt-in Cloud Review Client** | **✅ Implemented** | `src/cloud/satguardian_client.rs` (`SatguardianCloudClient::simplify`, `compile_equation_to_clauses()`) posts the pending minterms to the SATGuardian cloud synthesis service at `https://satguardian.tech/api/simplify` and compiles the answer into bitmask clauses. `auto_sync_enabled` defaults to `false` (`src/config.rs`, `waf_config.toml`), so no upload happens until the operator turns it on. |
| **Boolean Minimizer** | **❌ Not in this repository** | Minimization over `{AND, OR, NOT, XOR}` runs inside the SATGuardian cloud service. It is server-side, is not distributed to customers, and this audit could not review its code; the client only receives and evaluates the compiled clauses. |
| **Proposal Gate for Cloud Clauses** | **✅ Implemented** | `src/ledger/sqlite_ledger.rs` stores cloud clauses with `applied = 0` (`propose_dynamic_clause`); startup loads approved rows only (`load_applied_clauses`, `applied = 1`). Decisions are explicit operator actions behind the admin token: `satguardian-waf clauses list / apply / reject`, `GET /api/waf/clauses/pending`, `POST /api/waf/clauses/{id}/apply`, `DELETE /api/waf/clauses/{id}`. Rejecting deletes only a proposal; a rule already enforcing is never removed by it. |
| **Approved Clause Goes Live Without a Restart** | **✅ Implemented** | `SatguardianSatEngine::register_dynamic_clause` appends to the in-memory clause set the proxy shares through `Arc`; an HTTP approval is visible to subsequent requests with no process restart and no dropped connections. The earlier description of this step as automatic hot-reload of whatever the cloud returned is no longer true. |
| **Digital Twin Benign Traffic Replay** | **✅ Implemented** | `satguardian-advisor.py` (`SimulationAgent`) replays candidate rules against benign requests recorded in `waf_ledger.db` and reports collisions. It does not certify a fixed false-positive rate. |
| **Stateful Burst Rate Limiting** | **✅ Implemented** | `src/stateful/limiter.rs` (`StatefulRateLimiter`, per-client records behind an `RwLock<HashMap<..>>`) and `src/stateful/sliding_window.rs` (`SlidingWindowRingCounter`) count requests per client IP over a sliding window and raise the `SAT-STATE-01` violation that `src/engine/sat_solver.rs` turns into a block. *(There is no `DashMap` token bucket in this codebase; an earlier revision of this table claimed one.)* |
| **Wolfram Cellular Automata / M-Code / Graph Isomorphism** | **❌ Not in WAF Code** | Part of separate theoretical research projects (`hesize-code-ia`, `adn`); removed from all WAF documentation to maintain strict engineering accuracy. |

---

## 2. Reproducible Measurements

No value is capped or floored. The benchmark refuses to run without the pinned
corpus, and prints its scope on every run.

### 2.1 Detection: in-sample floors and the one held-out run

| Corpus | First run before fixes | Current regression | Nature of the number |
| :--- | :---: | :---: | :--- |
| `corpus/independent_v1.json` (63 attacks, 16 benign) | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) | 63/63, 0/16 blocked | In-sample regression floor |
| `corpus/heldout_v1.json` (17 attacks, 4 benign) | 11/17 recall (64.71%), 0/4 benign blocked | 17/17, 0/4 blocked | Consumed batch; in-sample regression floor |
| `corpus/heldout_v2.json` (98 attacks, 57 controls) | **55/98 recall (56.1%, 95% CI 46.3–65.5%)**, **4/57 controls blocked (7.0% FPR, 95% CI 2.8–16.7%)** | deliberately not re-run | Held-out, one run on 2026-11-04 (`corpus/heldout_v2_report.json`); superseded as the headline estimate |
| `benchmarks/real_comparative/corpus/heldout_v10.jsonl` (70 attacks, 44 controls) | current engine: **70/70 recall (100%, 95% CI 94.8–100%)**, **0/44 controls blocked (0.0% FPR, 95% CI 0.0–8.0%)**; frozen one-shot: **27/70 recall (frozen one-shot)**, 0/44 blocked | one-shot frozen in `corpus/heldout_v10_report.json`; current behaviour in `corpus/heldout_v10_post_tuning_report.json` | **Held-out batch, run once on 2026-11-08 before tuning — the publishable blind estimate is the frozen one-shot result; the 100%/0.0% is the current-engine diagnostic on the same batch** |
| `benchmarks/real_comparative/corpus/crs_v430.jsonl` (4,050 labelled attacks) | — | 3,321/4,050 detected (**82.0% recall**) | **Vendor in-sample** (CRS rule set's own tests; engine tuned on its misses — not independent) |

The first two corpora were used to drive fixes after their first run. Their
current 100%/0% therefore means "the pinned cases still pass", not "the engine
catches X% of real attacks". The `heldout_v10` row is the only out-of-sample
estimate available, it is a single run, and there is **no third-party or
independent evaluation** behind it. The earlier `heldout_v2` figure (56.1%/7.0%)
remains published for provenance; later batches v3–v9 were each measured once
and spent as tuning inputs. Protocol:
[corpus/README.md](corpus/README.md).

### 2.2 In-memory latency

`satguardian-waf benchmark -r 10000` on the same corpus, one representative run:

- **Total requests:** `10,000` (corpus cycled)
- **Single-thread throughput:** `~1,063 req/sec` (re-measured 2026-11-10; an earlier run reported 44,492 on a smaller rule set)
- **Min:** `11.9 µs`
- **p50:** `~458 µs` (re-measured 2026-11-10)
- **Mean:** `~937 µs`
- **p90:** `~2.6 ms`
- **p99:** `~6.0 ms` (varies with load)
- **Max:** `~11.4 ms`

Scope: in-memory rule evaluation only, on the pinned corpus. No TLS, proxy hop,
upstream service or stateful tracking is included, and no end-to-end request
path has been measured.

### 2.3 Python stand-in harness

`python run_benchmark.py 1000` compares the Python reference port against local
Python stand-ins. It does not execute Coraza, SafeLine, ModSecurity or an LLM.
The report prints the dataset provenance and a disclaimer next to the metrics.

### 2.4 Cloud Review, Verified Against Source

Checked line by line in `src/`:

- `auto_sync_enabled` defaults to **`false`** (`src/config.rs`, mirrored in
  `waf_config.toml`), so the node uploads nothing until the operator opts in.
- All three review entry points — the timer worker in `src/main.rs`,
  `satguardian-waf sync-simplify`, and `POST /api/waf/sync-simplify` — call
  `SqliteLedger::propose_dynamic_clause`, which writes `applied = 0`. The sync
  response returns `"status": "proposed"` and states that nothing was applied.
- `src/main.rs` calls `load_applied_clauses()` (`WHERE applied = 1`) at startup,
  so proposals never reach the engine implicitly.
- Enforcement requires an explicit decision: `satguardian-waf clauses apply
  <id>`, or `POST /api/waf/clauses/{id}/apply` for immediate registration on a
  running process. Both, together with `GET /api/waf/clauses/pending` and
  `DELETE /api/waf/clauses/{id}`, sit behind `require_admin_token`.
- `reject_dynamic_clause` deletes only rows with `applied = 0`; it cannot remove
  a rule that is already enforcing.
- The minimization itself is not verifiable from this repository: it runs in the
  SATGuardian cloud service, which is outside the audit scope.

---

## 3. Bundled Ledger Walkthrough (`waf_ledger.db`)

Running `python satguardian-advisor.py --report-md audit_report.md` against the
bundled ledger produces a demo, evidence-backed audit report:
- **Total recorded requests:** `3,799`
- **Blocked:** `2,136` (`951` SQLi, `477` XSS, `472` path traversal, `234` rate-limit bursts, `2` SSRF)
- **Allowed benign:** `1,663`
- **Replay:** candidate rules are replayed against the benign rows; collisions are reported per run. No fixed false-positive floor is claimed.
- **Pending minterms:** rows in `novel_anomalies` are **patterns awaiting analysis**. They are candidates for cloud review, not unprotected threats and not a coverage gap, and with `auto_sync_enabled = false` they stay on the node.

The ledger is demo data for exercising the advisor pipeline, not independently
labelled ground truth and not a customer tenant. No claim in this section should
be read as evidence about real traffic.

