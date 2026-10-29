# SATGuardian Methodology: Lexical Tokenization, Bitmask Evaluation & Offline Rule Minimization

**Technical Architecture Specification**  
**Codebase Reference:** `src/ast/lexer.rs`, `src/ast/features.rs`, `src/engine/sat_solver.rs`, `src/cloud/satguardian_client.rs`, `exactor-core-v128`

---

## 1. Architectural Separation: Hot Path vs. Offline Control Plane

A core engineering principle of **SATGuardian Edge WAF** is the strict separation between **in-path request evaluation** (which must execute in microseconds with predictable latency) and **out-of-band rule optimization** (which performs 128-variable algebraic boolean minimization asynchronously via **EXACTOR GXOR**).

| Subsystem | Execution Path | Implemented Algorithm | Computational Complexity | Measured Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Lexical Decoder & Tokenizer** | In-Path (Edge WAF) | Iterative URL/HTML decoding + comment stripping + token scan (`src/ast/lexer.rs`) | $O(L)$ where $L$ is payload byte length | `~6–10 µs` (Rust) |
| **Bitmask Rule Evaluator** | In-Path (Edge WAF) | 128-bit `FeatureVector` bitwise comparison (`src/engine/sat_solver.rs`) | $O(R)$ bitwise operations ($R \le 64$ rules) | `~4–6 µs` (Rust) |
| **Total Edge Hot Path** | **In-Path (Edge WAF)** | **Combined Lexer + Bitmask Evaluator** | **Linear in payload size, constant per rule** | **`13.60 µs` p50 / `14.53 µs` avg** |
| **EXACTOR GXOR Boolean Minimizer** | Out-of-Band (Cloud / Advisor) | Differential Gray Code Mapping + `{AND, OR, NOT, XOR}` reduction (`exactor-core-v128`) | $O(\text{term\_count})$ linear scaling up to 128 vars | `10–250 ms` (Background) |
| **Digital Twin Verifier** | Out-of-Band (`satguardian-advisor.py`) | Historical replay over benign SQLite ledger (`waf_ledger.db`) | $O(N_{\text{benign}})$ | `~50 ms` for `1,663` benign logs |

> **Important Clarification:** SATGuardian does **not** execute an NP-complete backtracking SAT solver (such as DPLL or CDCL) on the live HTTP request path, nor is it limited by the 20–30 variable exponential ceiling of classical Quine-McCluskey. Out-of-band logic minimization is powered by **EXACTOR GXOR**, which simplifies up to **128 Boolean variables (`u128`)** over `{AND, OR, NOT, XOR}` and compiles the reduced invariants into `u128` bitmasks for single-cycle bitwise evaluation on the edge.

---

## 2. Stage 1: Multi-Pass Lexical Normalization (`src/ast/lexer.rs`)

Attackers frequently evade traditional signature WAFs by nesting encodings (e.g., double or triple URL encoding `..%25252f`, HTML entity encoding, or inline SQL comments `/**/`).

SATGuardian's lexer (`Lexer::normalize_and_tokenize`) applies a bounded, deterministic normalization pipeline before extracting grammatical tokens:
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

During inspection, extracted lexical properties and HTTP metadata are packed into a 128-bit integer (`FeatureVector(pub u128)`):

```rust
// Fast O(1) bitwise evaluation of a compiled rule cube against the request minterm
#[inline(always)]
pub fn matches_minterm(minterm: u128, required_mask: u128, expected_bits: u128) -> bool {
    (minterm & required_mask) == expected_bits
}
```

### Why Bitmask Conjunctions Outperform Standalone Regexes
1. **Structural Context vs. Substring Matching:** A benign user comment containing the words `"script"` and `"character"` activates isolated keyword flags, which causes probabilistic token scorers to produce false positives (`24.6%` FPR in our 1,000-request benchmark). In SATGuardian, rule `SAT-XSS-01` requires the simultaneous presence of `TAG_OPEN` $\land$ `SCRIPT_ELEMENT` $\land$ `DOM_EXEC`, keeping the false positive rate below `0.1%`.
2. **Predictable CPU Execution:** Bitwise operations on a `u128` register execute in a few CPU clock cycles without backtracking, preventing Regular Expression Denial of Service (ReDoS).
3. **Human-Auditable Causal Traces:** Every blocked request records the exact rule ID, active token set, and boolean clause in `waf_ledger.db` (e.g., `(SELECT_PROJECTION AND UNION_CLAUSE) violates [SAT-SQLI-02] -> ACTION_BLOCK [sql_injection]`).

---

## 4. Stage 3: Out-of-Band EXACTOR GXOR Boolean Minimization (`src/cloud/satguardian_client.rs`, `exactor-core-v128`)

When the Edge WAF encounters anomalous high-entropy requests or repeated hostile bursts that do not match an existing compiled cube, it logs the observed 128-bit minterm in the `novel_anomalies` table of `waf_ledger.db`.

Out of band, `SatguardianCloudClient` (`src/cloud/satguardian_client.rs`) and the **Multi-Agent Advisor** (`satguardian-advisor.py`) invoke the **EXACTOR GXOR** engine (`procesar_gxor` in `exactor-core-v128`) to compress these `u128` minterms across up to **128 variables**:
1. **Differential Gray Code Mapping (`modify_gray_code`):** Rather than performing exhaustive $O(m^2)$ pairwise comparisons like classical Quine-McCluskey, EXACTOR projects `u128` minterms into Gray Code space and locates logical neighbors in $O(1)$ constant time via `BTreeMap`/`HashMap` lookups, achieving $O(\text{term\_count})$ linear scaling.
2. **GXOR / NXOR Algebraic Reduction over `{AND, OR, NOT, XOR}`:** Classical `{AND, OR, NOT}` minimizers suffer from exponential clause explosion when simplifying symmetric, parity, or cross-dependent security predicates. **EXACTOR GXOR** detects exclusive-OR (`XOR` / `NXOR`) parity structures natively and reduces them into compact algebraic invariants over `{AND, OR, NOT, XOR}` up to 128 variables.
3. **Digital Twin Replay (`SimulationAgent`):** Before any synthesized rule is applied, `satguardian-advisor.py` tests the candidate bitmask against all historical benign requests stored in `waf_ledger.db` (`1,663` benign requests in the current ledger) to verify `< 0.1%` false positives.
4. **Atomic Hot-Reload (`ArcSwap`):** Validated rules are compiled via `compile_equation_to_clauses` and hot-swapped into the running Rust Edge WAF via lock-free pointer replacement (`ArcSwap`) without dropping active TCP connections.
