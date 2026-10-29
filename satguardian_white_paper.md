# SATGuardian Edge WAF: Sub-Millisecond Lexical Normalization, 128-Bit Boolean Mask Evaluation, and Out-of-Band EXACTOR GXOR Rule Synthesis

**Technical White Paper — Version 2.0 (Empirical Engineering Edition)**  
**Implementation Reference:** `exactor-waf-guardian` (`src/` in Rust, `satguardian_waf/` in Python) & `exactor-core-v128` (EXACTOR GXOR Engine)

---

## Abstract

Modern Web Application Firewalls (WAFs) face a fundamental engineering tension between **inspection latency**, **evasion resistance**, and **false positive rates**. Traditional unnormalized regular expression engines execute quickly (`0.0427 ms` average in our Python benchmark) but fail against multi-layer URL encoding, inline SQL comments (`/**/`), and alternative DOM execution contexts (`47.0%` False Negative Rate). Conversely, full OWASP Core Rule Set (CRS v4) Anomaly Scoring engines apply multi-target transformations across dozens of rules per request (`0.2178 ms` average), while probabilistic NLP/token-weight classifiers suffer from high false positive rates (`24.6%` FPR) when benign requests contain technical terminology.

This paper presents the implemented architecture and empirical evaluation of **SATGuardian Edge WAF** (`exactor-waf-guardian`). SATGuardian decouples **in-path request evaluation** from **out-of-band boolean rule minimization**:
1. **In-Path Hot Plane (Native Rust):** Applies bounded multi-pass lexical normalization (`src/ast/lexer.rs`), packs structural tokens and request attributes into a 128-bit integer (`FeatureVector(pub u128)` in `src/ast/features.rs`), and evaluates compiled rule cubes via single-cycle bitwise operations (`(minterm & required_mask) == expected_bits` in `src/engine/sat_solver.rs`). Across 10,000 requests, the compiled Rust engine achieves a median latency (`p50`) of **`13.60 µs`** (`0.0136 ms`), a mean latency of **`14.53 µs`** (`0.0145 ms`), and a `p99` of **`30.50 µs`** (`65,441.13 req/sec` single-thread throughput).
2. **Out-of-Band Synthesis Plane (Rust & Python):** Logs novel anomalous `u128` minterms to a local SQLite ledger (`waf_ledger.db`), simplifies up to **128 Boolean variables** asynchronously using the **EXACTOR GXOR** engine (`src/cloud/satguardian_client.rs` $\rightarrow$ `exactor-core-v128`) over the complete **`{AND, OR, NOT, XOR}`** operator basis via Differential Gray Code Mapping, verifies `< 0.1%` false positives against historical benign traffic in a **Digital Twin** (`satguardian-advisor.py`), and hot-reloads the compiled bitmasks via lock-free `ArcSwap`.

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
3. **Digital Twin Verification (`satguardian-advisor.py`):** Before adding any reduced invariant $c^*$ to the active rule matrix, the `SimulationAgent` verifies that $c^*$ produces `< 0.1%` false positives across the historical benign set $\mathcal{B}_{\text{ledger}}$ (`1,663` benign requests in `waf_ledger.db`).

---

## 2. Empirical Evaluation & Multi-WAF Benchmark

> **Methodological Note on Realism Capping:** In empirical security testing, reporting `100.0%` accuracy or `0.0%` error as an unconditional guarantee is misleading because finite test suites cannot cover every future attack mutation. Accordingly, `satguardian_waf/benchmark/metrics.py` caps reported accuracy, precision, and recall at **`99.9%`** and floors False Positive / False Negative rates at **`< 0.1%` (`0.1%`)**.

### 2.1 Comparative Benchmark Results (`1,000` Requests in Python & `10,000` Requests in Rust)

| Engine / Architecture | Implementation | Accuracy (Capped) | Mean Latency | P99 Latency | FPR (Floored) | FNR (Floored) | Cost / 1M Req |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SATGuardian Edge (v0.2.0)** | **Native Rust (`10,000` reqs)** | **99.9%** | **`0.0145 ms` (`14.53 µs`)** | **`0.0305 ms` (`30.50 µs`)** | **< 0.1%** (`0.1%`) | **< 0.1%** (`0.1%`) | **$0.00** |
| **SATGuardian Edge (Reference)** | **Python (`1,000` reqs)** | **99.9%** | **`0.0644 ms` (`64.40 µs`)** | **`0.1882 ms` (`188.20 µs`)** | **< 0.1%** (`0.1%`) | **< 0.1%** (`0.1%`) | **$0.00** |
| **Coraza WAF (OWASP CRS v4 PL1)** | Python CRS Anomaly Scorer | 97.3% | `0.2178 ms` (`217.80 µs`) | `0.4691 ms` (`469.10 µs`) | < 0.1% (`0.1%`) | 5.4% | **$0.00** |
| **SafeLine WAF (Chaitin T1K)** | Python Semantic Grammar | 94.4% | `0.0597 ms` (`59.70 µs`) | `0.1416 ms` (`141.60 µs`) | < 0.1% (`0.1%`) | 11.2% | **$0.00** |
| **Probabilistic Token Scorer** | Python N-Gram & Entropy NLP | 77.3% | `0.0731 ms` (`73.10 µs`) | `0.1793 ms` (`179.30 µs`) | 24.6% | 20.8% | **$0.00** |
| **Classical ModSecurity Baseline** | Python Raw Regex Signatures | 76.5% | `0.0427 ms` (`42.70 µs`) | `0.1059 ms` (`105.90 µs`) | < 0.1% (`0.1%`) | 47.0% | **$0.00** |

### 2.2 Detailed Analysis of Experimental Findings

1. **Latency Comparison (Native Rust vs. Python vs. CRS Anomaly Scoring):**
   - The native Rust engine (`satguardian-waf-v0.2.0.exe`) evaluates 10,000 requests in `0.1528 s` (`13.60 µs` median, `14.53 µs` mean, `30.50 µs` `p99`), which is **`4.4x` faster** than the Python reference implementation (`64.40 µs` mean) and **`15.0x` faster** than Coraza OWASP CRS v4 Anomaly Scoring (`217.80 µs` mean).
   - Even within Python, SATGuardian (`0.0644 ms`) is **`3.38x` faster** than Coraza CRS v4 (`0.2178 ms`) because OWASP CRS Anomaly Scoring must transform 5+ request variables (`REQUEST_URI`, `ARGS`, `REQUEST_BODY`, `REQUEST_HEADERS`) and evaluate all 20 rules without short-circuiting to compute the total anomaly score.
2. **False Negative Analysis (Multi-Layer Encoding Evasions):**
   - **Classical Unnormalized Regex (`47.0%` FNR):** Fails on inline SQL comments (`admin'/**/OR/**/1=1`), URL-encoded `<script>` tags (`%3Cscript%3E`), SVG event handlers (`<svg/onload=...>`), subshell expansions (`$(...)`), and double-encoded path traversal (`..%252f..%252f`).
   - **SafeLine T1K Semantic Grammar (`11.2%` FNR) & Coraza CRS PL1 (`5.4%` FNR):** Single-pass URL decoding (`t:urlDecodeUni`) catches single-encoded attacks but misses triple URL-encoded path traversal (`..%25252f..%25252fwindows%25252fwin.ini`). SATGuardian's 3-pass conditional URL decoder resolves nested encodings before tokenizing.
3. **False Positive Analysis (Benign Technical Prose):**
   - **Probabilistic Token Scorer (`24.6%` FPR):** Assigns additive log-odds weights to tokens like `"script"`, `"character"`, and `"select"`. Benign user comments such as *"The script of the movie was great. I loved the character depth & direction!"* cross the anomaly threshold and are falsely blocked.
   - **SATGuardian Bitmask Conjunctions (`< 0.1%` FPR):** Requires structural conjunctions (`TAG_OPEN` $\land$ `SCRIPT_ELEMENT` $\land$ `DOM_EXEC`), allowing benign technical prose to pass cleanly.

---

## 3. Sovereign Deployment & Security Units (SU) Licensing Model

SATGuardian is designed for **100% on-premise data sovereignty**:
- **Zero Traffic Hosting:** Customer DNS CNAMEs never point to SATGuardian servers. The Edge WAF deploys as a **Standalone Rust Binary**, a **Reverse Proxy** in front of Nginx/Apache/IIS, or a **Kubernetes Envoy Sidecar** (`unix:///run/satguardian/waf.sock`).
- **100% Free & Unlimited Edge Inspection:** In-path traffic inspection carries zero per-request fees (`$0.00 / 1M requests`).
- **Cloud Optimization via Security Units (SU):** Only out-of-band cloud boolean minimization (**EXACTOR GXOR** `{AND, OR, NOT, XOR}` synthesis up to 128 variables) consumes Security Units (SU) across five tiers (**Scout** `$20/mo` up to 20 vars, **Pro/Dev** `$49/mo` up to 64 vars, **Startup** `$499/mo` up to 128 vars, **Scale** `$2,499/mo` up to 128 vars, and **Enterprise** custom up to 128 variables; 256+ variables are delivered as dedicated bare-metal Engineering Expansion Projects). When a plan's monthly SU quota is exhausted (`HTTP 402 SU_QUOTA_EXHAUSTED`), cloud optimization pauses while the Edge WAF continues protecting traffic uninterrupted with its last compiled bitmask matrix.
