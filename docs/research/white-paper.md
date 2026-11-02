# SATGuardian Edge WAF: Sub-Millisecond Lexical Normalization, 128-Bit Boolean Mask Evaluation, and Out-of-Band EXACTOR GXOR Rule Synthesis

**Technical White Paper — Version 3.0 (Research Prototype Edition)**  
**Implementation Reference:** `satguardian` (`src/` in Rust, `satguardian_waf/` in Python) & `exactor-core-v128` (EXACTOR GXOR Engine)

> **Status: research prototype, not a production-ready WAF.** Evaluation is
> in-sample on a small hand-written corpus; competitor rows are local Python
> stand-ins. See [Project Status](../status.md).

---

## Abstract

Modern Web Application Firewalls (WAFs) face a fundamental engineering tension between **inspection latency**, **evasion resistance**, and **false positive rates**. Unnormalized regular expression engines are cheap per request but miss nested encodings and inline comments. Anomaly-scoring rule sets transform several request targets and evaluate many rules. Token-weight classifiers can fire on benign technical prose. Those statements are design-level; this repository does not benchmark the real products, only local Python stand-ins.

This paper presents the implemented architecture and the measurements available for **SATGuardian Edge WAF** (`satguardian`). SATGuardian decouples **in-path request evaluation** from **out-of-band boolean rule minimization**:
1. **In-Path Hot Plane (Native Rust):** Applies bounded multi-pass lexical normalization (`src/ast/lexer.rs`), packs structural tokens and request attributes into a 128-bit integer (`FeatureVector(pub u128)` in `src/ast/features.rs`), and evaluates compiled rule cubes via bitwise operations (`(minterm & required_mask) == expected_bits` in `src/engine/sat_solver.rs`). On the pinned corpus at 10,000 requests, a representative run measured p50 `~20 µs`, mean `~22 µs`, and p99 near `50 µs`, single-threaded, in memory only.
2. **Out-of-Band Synthesis Plane (Rust & Python):** Logs novel anomalous `u128` minterms to a local SQLite ledger (`waf_ledger.db`), simplifies up to **128 Boolean variables** asynchronously using the **EXACTOR GXOR** engine over the complete **`{AND, OR, NOT, XOR}`** operator basis via Differential Gray Code Mapping, replays candidates against recorded benign traffic to find collisions, and hot-reloads compiled bitmasks via lock-free `ArcSwap`.

---

## 1. Mathematical & Algorithmic Formulation (As Implemented)

### 1.1 Lexical Normalization & Feature Vector Mapping
Let an incoming HTTP request be represented by the tuple $r = (M, P, Q, H, B)$ denoting method, path, query string, headers, and body.

The lexical normalizer $\mathcal{N}$ (`src/ast/lexer.rs`) applies bounded iterative percent-decoding ($k \le 3$ passes) and inline comment stripping (`/*...*/`) to produce a canonical byte stream $s = \mathcal{N}(r)$, from which it extracts a set of structural tokens $\mathcal{T}(s)$ and maps $r$ into a 128-bit boolean feature vector:

$$\mathbf{v}(r) \in \{0, 1\}^{128} \quad (\text{represented in Rust as } \texttt{u128})$$

Each bit $v_i \in \{0, 1\}$ ($i \in \{0, \dots, 127\}$) encodes a deterministic predicate (e.g., presence of SQL tautology tokens, `UNION SELECT` projection, executable `<script>` or inline DOM event attributes, shell command chaining operators, relative path traversal sequences, or high character Shannon entropy $H(s) > \tau$).

### 1.2 In-Path Bitmask Cube Evaluation (`src/engine/sat_solver.rs`)
Each compiled security rule $c_j$ is a boolean cube (product term / conjunction of literals) represented by two 128-bit integers:
- `required_mask` ($M_j \in \texttt{u128}$): Bitmask indicating which of the 128 variables participate in rule $j$.
- `expected_bits` ($E_j \in \texttt{u128}$): Expected polarity (`1` for positive literal, `0` for negated literal) of those active variables.

At runtime, evaluating whether request $\mathbf{v}(r)$ triggers rule $c_j$ requires a single bitwise `AND` and equality check:

$$\text{Match}(\mathbf{v}(r), c_j) \iff (\mathbf{v}(r) \mathbin{\&} M_j) == E_j$$

If no rule cube matches ($\forall j, \, (\mathbf{v}(r) \mathbin{\&} M_j) \neq E_j$), the security invariant holds and the request is allowed. Unlike backtracking regular expressions or NP-complete in-path DPLL/CDCL solvers, bitwise evaluation over $R$ rules executes in deterministic $O(R)$ CPU cycles.

### 1.3 Out-of-Band EXACTOR GXOR Minimization (`src/cloud/satguardian_client.rs`, `exactor-core-v128`)
When unobserved malicious minterms $\mathcal{M} = \{m_1, m_2, \dots, m_k\} \subset \{0, 1\}^{n}$ ($n \le 128$) are collected in `waf_ledger.db`, classical `{AND, OR, NOT}` minimizers (such as Quine-McCluskey or Espresso) suffer from $O(2^n)$ exponential blow-up beyond 20–30 variables. Instead, the out-of-band synthesizer invokes the **EXACTOR GXOR** engine (`procesar_gxor` in `exactor-core-v128`) via `SatguardianCloudClient::simplify`:
1. **Differential Gray Code Mapping (`modify_gray_code`):** Projects 128-bit minterms into a Gray Code space and locates logical neighbors differing by a single bit ($\text{popcount}(E_a \oplus E_b) = 1$) in $O(1)$ constant time via `BTreeMap`/`HashMap` lookups, achieving $O(\text{term\_count})$ linear complexity:
   $$M_{\text{merged}} = M_a \mathbin{\&} \neg(E_a \oplus E_b), \quad E_{\text{merged}} = E_a \mathbin{\&} M_{\text{merged}}$$
2. **GXOR / NXOR Algebraic Reduction over `{AND, OR, NOT, XOR}`:** Detects exclusive-OR ($\oplus$) and equivalence ($\odot$) structures across up to **128 Boolean variables (`u128`)**, collapsing parity and symmetric attack predicates that would otherwise require exponentially many Sum-of-Products (SOP) clauses.
3. **Digital Twin Collision Replay (`satguardian-advisor.py`):** Before a reduced invariant $c^*$ is added to the active rule matrix, the `SimulationAgent` replays it against the benign records stored in `waf_ledger.db` and reports any collision. The ledger in this repository is demo data, so the replay finds collisions; it does not certify a fixed false-positive rate.

---

## 2. Evaluation: What Was Measured, and What Was Not

> **No vendor comparison has been run.** The Python harness in this repository
> contains local stand-ins for a CRS-style anomaly scorer, a semantic ruleset and
> a token-weight classifier. They are Python reimplementations written here, not
> Coraza, SafeLine, ModSecurity or any commercial product. Their numbers describe
> this repository's stand-ins only.

### 2.1 Detection on the Pinned Corpus

`corpus/independent_v1.json` holds 63 labelled attacks and 16 benign controls;
`corpus/heldout_v1.json` holds 17 attack variants and 4 benign controls. The
first run of each file was recorded before any fix and is the only number in
this repository that was not produced by tuning against the same data.

| Corpus | First run (before fixes) | Current regression run | Interpretation |
| :--- | :---: | :---: | :--- |
| `independent_v1` | 51/63 attacks (80.95%), 3/16 benign blocked (18.75%) | 63/63 attacks, 0/16 benign blocked | In-sample regression after fixes |
| `heldout_v1` | 11/17 attacks (64.71%), 0/4 benign blocked (0.00%) | 17/17 attacks, 0/4 benign blocked | Batch consumed by the fix pass; in-sample now |

The first-run row is the honest statement about the engine as originally
published: it missed roughly one attack in five and blocked three benign
requests. The current row says the pinned cases pass. It is not a held-out
estimate and it is not evidence of production accuracy. Rules for adding cases
and the full miss list live in [Detection Corpus](../corpus.md).

### 2.2 In-Memory Latency (Native Rust)

`satguardian-waf benchmark -r 10000` cycles the corpus and measures rule
evaluation only. A representative run on the development machine reported p50
near `20 µs`, mean near `22 µs` and p99 near `50 µs`, single-threaded. The
figures move with machine load and should be re-measured on the target host.
Excluded from the measurement: network, TLS, reverse-proxy hops, upstream
calls, and SQLite ledger writes. The runner prints these exclusions and the
in-sample caveat on every run, and it refuses to start if the corpus file is
missing.

### 2.3 Python Reference Harness (Local Stand-Ins)

`python run_benchmark.py 1000` runs the Python reference port of the engine
against the local stand-ins on the in-repo payload list. Every row is labelled
with its provenance in the report output, the Markdown export and the API
response. Representative 1,000-request values:

| Engine | Implementation | Attacks detected | Benign blocked | Mean latency |
| :--- | :---: | :---: | :---: | :---: |
| SATGuardian Python reference | Python port (not the Rust engine) | 100.0% | 0.0% | `~0.06 ms` |
| CRS-style anomaly stand-in | Python reimplementation | 97.3% | 0.0% | `~0.24 ms` |
| Semantic-ruleset stand-in | Python reimplementation | 94.4% | 0.0% | `~0.06 ms` |
| Token-weight stand-in | Python heuristic | 77.3% | 24.6% | `~0.07 ms` |
| Unnormalized regex stand-in | Python reimplementation | 76.5% | 0.0% | `~0.04 ms` |

Both the payload list and the stand-ins were written in this repository, so
these are in-sample results over a small hand-written set. They show that the
harness runs end to end. They do not support any claim about real products, and
they do not establish production readiness.

### 2.4 Engineering Takeaways

1. **Normalization drives the detection gap.** The first-run misses were
   concentrated in MySQL executable comments, `||` tautologies, HTML-entity
   schemes, overlong UTF-8, `\u`-escaped keys and nested Log4Shell lookups. The
   fixes were lexical: additional decoding passes and normalization rules, not a
   larger rule table.
2. **Structural conjunctions avoid keyword false positives in the pinned set.**
   The three first-run false positives were a `<script src>` include, a `data:`
   URI and a `localhost` URL in prose. Requiring co-occurring structural tokens
   removed them without deleting the cases.
3. **Per-request cost is dominated by normalization, not rule matching.** The
   bitmask test is one `AND` plus one comparison per rule; the decode loop runs
   first and sets the floor. This ordering is why the in-memory figure is tens of
   microseconds rather than single digits.
4. **None of this is an independent evaluation.** The corpus is small and
   hand-written, and it has been used to drive fixes. A defensible quality claim
   needs a held-out corpus built and labelled by someone who has not seen the
   engine, plus a production soak. Neither exists yet. See [Project Status](../status.md).

---

## 3. Sovereign Deployment & Security Units (SU) Licensing Model

SATGuardian is designed for **100% on-premise data sovereignty**:
- **Zero Traffic Hosting:** Customer DNS CNAMEs never point to SATGuardian servers. The Edge WAF deploys as a **Standalone Rust Binary**, a **Reverse Proxy** in front of Nginx/Apache/IIS, or a **Kubernetes Envoy Sidecar** (`unix:///run/satguardian/waf.sock`).
- **100% Free & Unlimited Edge Inspection:** In-path traffic inspection carries zero per-request fees (`$0.00 / 1M requests`).
- **Cloud Optimization via Security Units (SU):** Only out-of-band cloud boolean minimization (**EXACTOR GXOR** `{AND, OR, NOT, XOR}` synthesis up to 128 variables) consumes Security Units (SU) across five tiers (**Scout** `$20/mo` up to 20 vars, **Pro/Dev** `$49/mo` up to 64 vars, **Startup** `$499/mo` up to 128 vars, **Scale** `$2,499/mo` up to 128 vars, and **Enterprise** custom up to 128 variables; 256+ variables are delivered as dedicated bare-metal Engineering Expansion Projects). When a plan's monthly SU quota is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud optimization pauses while the Edge WAF continues serving traffic with its last compiled bitmask matrix.
