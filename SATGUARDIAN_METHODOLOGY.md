# SATGuardian Methodology: Lexical Tokenization, Bitmask Evaluation & Out-of-Band Cloud Rule Review

**Technical Architecture Specification**  
**Codebase Reference:** `src/ast/lexer.rs`, `src/ast/features.rs`, `src/engine/sat_solver.rs`, `src/cloud/satguardian_client.rs`, `src/ledger/sqlite_ledger.rs`, `src/api/server.rs`

> **Status: SATGuardian Edge WAF v0.3.0.** Detection evidence is limited to a small
> in-sample corpus plus one held-out run of hand-written payloads, and there is
> no third-party evaluation; see [STATUS.md](STATUS.md).

---

## 1. Architectural Separation: Hot Path vs. Opt-In Control Plane

A core engineering principle of **SATGuardian Edge WAF** is the strict separation between **in-path request evaluation** (which must execute in microseconds with predictable latency) and **out-of-band rule review** (which is opt-in, runs against the SATGuardian cloud service, and ends in a proposal the operator approves).

| Subsystem | Execution Path | Implemented Algorithm | Computational Complexity | Measured Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Lexical Decoder & Tokenizer** | In-Path (Edge WAF) | Iterative URL/HTML decoding + comment stripping + token scan (`src/ast/lexer.rs`) | $O(L)$ where $L$ is payload byte length | `~6–10 µs` (Rust, in-memory) |
| **Bitmask Rule Evaluator** | In-Path (Edge WAF) | 128-bit `FeatureVector` bitwise comparison (`src/engine/sat_solver.rs`) | $O(R)$ bitwise operations ($R \le 64$ rules) | `~4–6 µs` (Rust, in-memory) |
| **Total Edge Hot Path** | **In-Path (Edge WAF)** | **Combined Lexer + Bitmask Evaluator** | **Linear in payload size, constant per rule** | **`~0.46 ms` p50 / `~0.94 ms` avg (in-memory, re-measured 2026-11-10)** |
| **SATGuardian cloud synthesis** | **Outside this repository** (the service at `satguardian.tech`) | Boolean minimization over the `{AND, OR, NOT, XOR}` basis | Not characterized here; the client does not ship or run a minimizer | Not measured in this repository |
| **Clause compiler (client side)** | Out-of-Band (`src/cloud/satguardian_client.rs`) | `compile_equation_to_clauses()` parses the returned equation into `(required_mask, expected_bits)` pairs | Linear in the number of literals | Not measured in this repository |
| **Digital Twin Verifier** | Out-of-Band (`satguardian-advisor.py`) | Historical replay over benign SQLite ledger (`waf_ledger.db`) | $O(N_{\text{benign}})$ | `~50 ms` for `1,663` benign logs in the bundled demo ledger |

> **Important Clarification:** SATGuardian does **not** execute an NP-complete backtracking SAT solver (such as DPLL or CDCL) on the live HTTP request path. The request path is a bitwise conjunction test over a fixed-width `u128` feature vector. The algebraic minimization that turns recorded minterms into compact clauses is a property of the **SATGuardian cloud synthesis** service: it runs server-side, it is not distributed to customers, and this repository contains only the client that calls it, the code that compiles its answer into bitmasks, and the code that evaluates those bitmasks after an operator approves them.

---

## 2. Stage 1: Multi-Pass Lexical Normalization (`src/ast/lexer.rs`)

Attackers frequently evade traditional signature WAFs by nesting encodings (e.g., double or triple URL encoding `..%25252f`, HTML entity encoding, or inline SQL comments `/**/`).

SATGuardian's lexer (`AstLexer`, with `normalize_string` for the decode passes and `tokenize_request` for the request path) applies a bounded, deterministic normalization pipeline before extracting grammatical tokens:
1. **Iterative Percent-Decoding:** Unwinds nested URL encodings up to a fixed recursion bound so obfuscated sequences resolve to their canonical ASCII characters.
2. **Comment & Whitespace Canonicalization:** Strips inline C/SQL comments (`/* ... */`) and collapses redundant whitespace so `UNION/**/ALL/**/SELECT` normalizes cleanly.
3. **Contextual Token Extraction:** Scans the normalized stream to identify structural tokens across five security domains ("Certainty Islands"):
   - `ISLAND-SQLI`: Quote delimiters, boolean tautologies (`'1'='1'`, `1=1`), `UNION SELECT` projections, stacked DDL (`; DROP TABLE`), and time-delay primitives (`SLEEP`, `WAITFOR DELAY`, `BENCHMARK`).
   - `ISLAND-XSS`: Executable `<script>` blocks, inline DOM event handlers (`onerror=`, `onload=`), `<svg/onload>`, and `javascript:`/`data:` pseudo-protocols.
   - `ISLAND-RCE`: Shell chaining operators (`;`, `|`, `&&`, `` ` ``, `$()`) coupled with system binaries (`cat`, `whoami`, `bash`, `curl`, `powershell`) or dynamic evaluation sinks (`os.system`, `eval()`, `subprocess`).
   - `ISLAND-LFI`: Directory traversal sequences (`../`, `..\`) and direct kernel/system file descriptors (`/etc/passwd`, `/proc/self/environ`, `win.ini`).
   - `ISLAND-SSRF`: Internal cloud metadata targets (`169.254.169.254`), loopback addresses (`127.0.0.1`, `localhost`), and non-HTTP proxy schemes (`gopher://`, `dict://`, `file://`).

---

## 3. Stage 2: 128-Bit Feature Vector & Bitmask Evaluation (`src/ast/features.rs`, `src/engine/sat_solver.rs`)

During inspection, extracted lexical properties and HTTP metadata are packed into a 128-bit integer (`FeatureVector { bits: u128 }`; the current catalogue names 40 of those bits):

```rust
// src/engine/sat_solver.rs — conjunction test for an approved compiled clause
let dyn_rules = self.dynamic_clauses.read().unwrap();
for clause in dyn_rules.iter() {
    if (fv.bits & clause.required_mask) == clause.expected_bits {
        // the request violates this clause: record the rule id, the active token
        // set and the boolean formula in the causal proof trace
    }
}
```

### Why SATGuardian Uses Bitmask Conjunctions
1. **Structural Context vs. Substring Matching:** A benign user comment containing the words `"script"` and `"character"` activates isolated keyword flags, which causes the local token-weight stand-in to produce false positives (`24.6%` on the in-repo stream). In SATGuardian, rule `SAT-XSS-01` requires the simultaneous presence of `TAG_OPEN` $\land$ `SCRIPT_ELEMENT` $\land$ `DOM_EXEC`; the pinned corpus records no benign collision for it, which is an in-sample regression observation. The current held-out batch (`benchmarks/real_comparative/corpus/heldout_v10.jsonl`) was run once on 2026-11-08 before any fix: the frozen one-shot estimate is frozen one-shot result on 70 attacks and **0.0% false-positive rate on 44 controls** (95% CI 0.0–8.0%), and the current engine measures **100%/0.0%** on the same batch as a post-tuning diagnostic. The earlier `heldout_v2` figure (56.1%/7.0%) remains for provenance, and no third-party evaluation exists.
2. **Predictable CPU Execution:** Bitwise operations on a `u128` register execute in a few CPU clock cycles without backtracking, which is why the hot path has no ReDoS-style blow-up on the corpus payloads.
3. **Human-Auditable Causal Traces:** Every blocked request records the exact rule ID, active token set, and boolean clause in `waf_ledger.db` (e.g., `(SELECT_PROJECTION AND UNION_CLAUSE) violates [SAT-SQLI-02] -> ACTION_BLOCK [sql_injection]`).

---

## 4. Stage 3: Out-of-Band Cloud Review, Replay and Approval (`src/cloud/satguardian_client.rs`, `src/ledger/sqlite_ledger.rs`, `satguardian-advisor.py`, `src/api/server.rs`)

When the Edge WAF encounters anomalous high-entropy requests or repeated hostile bursts that do not match an existing compiled cube, it logs the observed 128-bit minterm in the `novel_anomalies` table of `waf_ledger.db`. Those rows are **patterns awaiting analysis**: they say the engine did not recognize the shape, not that the shape got through.

Review is **opt-in**. `auto_sync_enabled` defaults to `false` in `src/config.rs` and in `waf_config.toml`, so with the shipped configuration no minterm ever leaves the node. When an operator enables it, runs `satguardian-waf sync-simplify`, or calls the token-authenticated `POST /api/waf/sync-simplify`, the client bundles the variable catalogue plus the pending minterms and `POST`s them to the SATGuardian cloud synthesis service at `https://satguardian.tech/api/simplify`.

What happens next is deliberately split in two:

1. **Minimization on the service.** The reduction of those minterms into a compact equation over the `{AND, OR, NOT, XOR}` basis is performed by the SATGuardian cloud synthesizer. It is server-side code: it is not in this repository, it is not distributed to customers, and its internal algorithm and clause-count behaviour are not characterized by anything in this codebase.
2. **Compilation on the client.** `SatguardianCloudClient::compile_equation_to_clauses` (`src/cloud/satguardian_client.rs`) parses the returned equation into `(required_mask, expected_bits)` pairs — the same representation the built-in rules use, so evaluation stays a single `AND` plus a comparison. A response the client cannot parse is rejected with `invalid_cloud_equation`; nothing is loaded on a parse failure.
3. **Storage as proposals.** Each compiled clause is written to `dynamic_clauses` with `applied = 0` (`SqliteLedger::propose_dynamic_clause`). It does not enter the running engine, and startup ignores it: `load_applied_clauses()` selects `applied = 1` only. The sync response states this — `"status": "proposed"`, "Nothing was applied to the running rule set".
4. **Replay evidence for the operator.** The advisor (`satguardian-advisor.py`) replays candidate bitmasks against the benign requests recorded in `waf_ledger.db` and reports collisions per run, so the person deciding can see what the candidate would have blocked. The gate is only as good as the recorded benign traffic; it does not establish a fixed false-positive rate.
5. **Approval, the only step that changes enforcement.** `satguardian-waf clauses apply <id>` marks a proposal approved (it registers when the proxy starts); `POST /api/waf/clauses/{id}/apply` additionally calls `engine.register_dynamic_clause()` on the live process, so new requests see it without restarting the proxy or dropping connections. `clauses reject <id>` / `DELETE /api/waf/clauses/{id}` deletes only a proposal — a rule already enforcing is never removed by it. All of these sit behind the existing admin token.

The practical consequence is the product promise: the node protects itself for free and offline; the paid service contributes continuous review of new patterns, proposals and explanations; and the operator stays in control of what the WAF actually enforces.
