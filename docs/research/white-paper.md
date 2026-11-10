# SATGuardian Edge WAF: Tens-of-Microseconds Lexical Normalization, 128-Bit Boolean Mask Evaluation, and Opt-In Out-of-Band Cloud Rule Review

**Technical White Paper — Version 3.0**  
**Implementation Reference:** `satguardian` (`src/` in Rust, `satguardian_waf/` in Python). The Boolean minimizer is a service at `satguardian.tech`; only its client lives in this repository.

> **Status: SATGuardian Edge WAF v0.3.0.** Evaluation is
> in-sample on a small hand-written corpus plus one held-out run of hand-written
> payloads; competitor rows are local Python stand-ins; no third-party
> evaluation exists. See [STATUS.md](../status.md).

---

## Abstract

Modern Web Application Firewalls (WAFs) face a fundamental engineering tension between **inspection latency**, **evasion resistance**, and **false positive rates**. Unnormalized regular expression engines are cheap per request but miss nested encodings and inline comments. Anomaly-scoring rule sets transform several request targets and evaluate many rules. Token-weight classifiers can fire on benign technical prose. Those statements are design-level; this repository does not benchmark the real products, only local Python stand-ins.

This paper presents the implemented architecture and the measurements available for **SATGuardian Edge WAF** (`satguardian`). SATGuardian decouples **in-path request evaluation** from **out-of-band rule review**, and puts an operator decision between the two:
1. **In-Path Hot Plane (Native Rust):** Applies bounded multi-pass lexical normalization (`src/ast/lexer.rs`), packs structural tokens and request attributes into a 128-bit integer (`FeatureVector { bits: u128 }` in `src/ast/features.rs`), and evaluates compiled rule cubes via bitwise operations (`(fv.bits & required_mask) == expected_bits` in `src/engine/sat_solver.rs`). On the pinned corpus at 10,000 requests, a representative run measured p50 `~20 µs`, mean `~22 µs`, and p99 near `50 µs`, single-threaded, in memory only.
2. **Out-of-Band Review Plane (Rust & Python, opt-in):** Logs anomalous `u128` minterms to a local SQLite ledger (`waf_ledger.db`). Only if the operator turns cloud review on (`auto_sync_enabled`, `false` by default) are those minterms sent to **SATGuardian cloud synthesis** at `satguardian.tech`, which minimizes them over the `{AND, OR, NOT, XOR}` basis server-side. The client compiles the returned equation into bitmask clauses and stores them as **proposals** (`dynamic_clauses.applied = 0`). Nothing is enforced until the operator approves a proposal; approved clauses then register in the running engine without a restart.

---

## 1. Mathematical & Algorithmic Formulation (As Implemented)

### 1.1 Lexical Normalization & Feature Vector Mapping
Let an incoming HTTP request be represented by the tuple $r = (M, P, Q, H, B)$ denoting method, path, query string, headers, and body.

The lexical normalizer $\mathcal{N}$ (`src/ast/lexer.rs`) applies bounded iterative percent-decoding ($k \le 3$ passes) and inline comment stripping (`/*...*/`) to produce a canonical byte stream $s = \mathcal{N}(r)$, from which it extracts a set of structural tokens $\mathcal{T}(s)$ and maps $r$ into a 128-bit boolean feature vector:

$$\mathbf{v}(r) \in \{0, 1\}^{128} \quad (\text{represented in Rust as } \texttt{u128})$$

Each bit $v_i \in \{0, 1\}$ ($i \in \{0, \dots, 127\}$) encodes a deterministic predicate (e.g., presence of SQL tautology tokens, `UNION SELECT` projection, executable `<script>` or inline DOM event attributes, shell command chaining operators, relative path traversal sequences, or high character Shannon entropy $H(s) > \tau$). The `u128` container addresses up to 128 variables; the catalogue in `src/ast/features.rs` names 40 of them today, and that catalogue is exactly what the client sends to the cloud service.

### 1.2 In-Path Bitmask Cube Evaluation (`src/engine/sat_solver.rs`)
Each compiled security rule $c_j$ is a boolean cube (product term / conjunction of literals) represented by two 128-bit integers:
- `required_mask` ($M_j \in \texttt{u128}$): Bitmask indicating which positions of the vector participate in rule $j$.
- `expected_bits` ($E_j \in \texttt{u128}$): Expected polarity (`1` for positive literal, `0` for negated literal) of those active variables.

At runtime, evaluating whether request $\mathbf{v}(r)$ triggers rule $c_j$ requires a single bitwise `AND` and equality check:

$$\text{Match}(\mathbf{v}(r), c_j) \iff (\mathbf{v}(r) \mathbin{\&} M_j) == E_j$$

If no rule cube matches ($\forall j, \, (\mathbf{v}(r) \mathbin{\&} M_j) \neq E_j$), the security invariant holds and the request is allowed. Unlike backtracking regular expressions or NP-complete in-path DPLL/CDCL solvers, bitwise evaluation over $R$ rules executes in deterministic $O(R)$ CPU cycles.

### 1.3 Out-of-Band Cloud Synthesis and the Approval Gate (`src/cloud/satguardian_client.rs`, `src/ledger/sqlite_ledger.rs`, `src/api/server.rs`)
When previously unobserved minterms $\mathcal{M} = \{m_1, m_2, \dots, m_k\} \subset \{0, 1\}^{n}$ ($n \le 128$) accumulate in `waf_ledger.db`, the client can ask the service to reduce them:

1. **Request.** `SatguardianCloudClient::simplify` posts the variable catalogue and the pending minterms to `https://satguardian.tech/api/simplify`. This only happens if the operator opted in: `auto_sync_enabled` is `false` by default in `src/config.rs` and `waf_config.toml`.
2. **Minimization, server-side.** Reducing $\mathcal{M}$ to a compact formula $c^*$ over $\{\land, \lor, \neg, \oplus\}$ is done by **SATGuardian cloud synthesis**. That minimizer is not part of this repository, is not distributed to customers, and its internal algorithm and reduction behaviour are not characterized by any measurement here.
3. **Compilation, client-side.** `compile_equation_to_clauses()` parses the returned equation into runtime pairs $(M_j, E_j)$, i.e. `(required_mask, expected_bits)`, so the hot path stays a single `AND` plus one comparison per clause. An equation that does not parse is refused (`invalid_cloud_equation`) and the ledger is left unchanged.
4. **Proposal, not enforcement.** Each clause is stored with `applied = 0` (`SqliteLedger::propose_dynamic_clause`). The running engine does not see it and startup skips it — `load_applied_clauses()` selects `applied = 1` only. The HTTP response says so: `"status": "proposed"`.
5. **Digital-twin replay as evidence.** `satguardian-advisor.py` (`SimulationAgent`) replays candidate bitmasks against the benign records in `waf_ledger.db` and reports collisions per run, so the operator decides with the replay in front of them. On the bundled demo ledger the current run prints, for example, `154 collisions` for the hostile-IP candidate and `No collisions / 1663 allowed` for the method-restriction candidates. The ledger is demo data, so neither outcome establishes a false-positive rate.
6. **Approval.** `satguardian-waf clauses apply <id>` or `POST /api/waf/clauses/{id}/apply` (admin token) registers one clause in the engine; the HTTP call applies it to the live process, the CLI applies it from the next start. `reject` deletes only a proposal and never removes a rule already enforcing.

---

## 2. Evaluation: What Was Measured, and What Was Not

> **One real-product comparison exists.** Section 2.5 reports a 2026-11-09
> head-to-head against Aegis Community Edition v1.1.0 (Coraza engine, bundled
> OWASP CRS 4.25.1, paranoia level 1) over real HTTP. All other competitor
> rows in this repository are local Python stand-ins — not Coraza, SafeLine,
> ModSecurity or any commercial product — and their numbers describe this
> repository's stand-ins only.

### 2.1 Detection: In-Sample Floors and the One Held-Out Measurement

`corpus/independent_v1.json` holds 63 labelled attacks and 16 benign controls;
`corpus/heldout_v1.json` holds 17 attack variants and 4 benign controls. Both
were used to drive fixes after their first run, so their current scores are
regression floors. `corpus/heldout_v2.json` (98 attacks, 57 controls) was
labelled first and run **once**, before any fix. The current out-of-sample
measurement is `benchmarks/real_comparative/corpus/heldout_v10.jsonl`
(70 attacks, 44 controls), also run **once** before any fix on 2026-11-08;
the `heldout_v2` figure (56.1%/7.0%) remains for provenance.

| Corpus | First run (before fixes) | Current regression run | Interpretation |
| :--- | :---: | :---: | :--- |
| `independent_v1` | 51/63 attacks (80.95%), 3/16 benign blocked (18.75%) | 63/63 attacks, 0/16 benign blocked | In-sample regression floor after fixes |
| `heldout_v1` | 11/17 attacks (64.71%), 0/4 benign blocked (0.00%) | 17/17 attacks, 0/4 benign blocked | Batch consumed by the fix pass; in-sample regression floor |
| `heldout_v2` | **55/98 attacks (56.1% recall, 95% CI 46.3–65.5%)**, **4/57 controls blocked (7.0% FPR, 95% CI 2.8–16.7%)** | not re-run; tuning against it would invalidate the batch | Held-out, one run on 2026-11-04; superseded as the headline estimate |
| `heldout_v10` | current engine: **70/70 attacks (100% recall)**, **0/44 controls blocked (0.0% FPR)**; frozen one-shot: **27/70 (38.6% recall)**, 0/44 blocked | one-shot frozen in `corpus/heldout_v10_report.json`; current behaviour in `corpus/heldout_v10_post_tuning_report.json` | **Held-out batch measured once on 2026-11-08 before tuning** — the publishable blind estimate is the frozen 38.6%/0.0%; 100%/0.0% is the current-engine diagnostic |

The `heldout_v10` row is the number to quote today: on a harder batch — protocol
bodies, query DSLs and admin surfaces the earlier corpora never covered — the
engine caught 27 of 70 attacks with zero false positives. The earlier v2 figure
(56.1%/7.0%) stays published for provenance; batches v3–v9 were each measured
once and spent as tuning inputs, and `heldout_v2_report.json` /
`heldout_v10_report.json` carry the per-category breakdowns and every
individual miss. The current 100%/0% regression rows mean only that the pinned
cases still pass; they are not held-out estimates and they are not evidence of
accuracy on real traffic. There is **no third-party or independent
evaluation**: every batch, including `heldout_v10`, was written inside this
project from public payload catalogues and labelled by the same side that owns
the engine, and its benign controls are imagined traffic, not a sample from a
real access log. Rules for adding cases and the full miss list live in
[corpus/README.md](../corpus.md).

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
4. **One held-out run is not an independent evaluation.** `heldout_v10.jsonl`
   is a real out-of-sample measurement of *those* payloads — the frozen one-shot
   recorded **38.6% recall (95% CI 28.0–50.3%)** and **0.0% false-positive rate
   (95% CI 0.0–8.0%)**, while the current engine measures 100%/0.0% on the same
   batch as a post-tuning diagnostic. The earlier batches (including `heldout_v2`
   at 56.1%/7.0%) are regression floors. A defensible
   quality claim still needs batches built and labelled by people outside this
   project, repeated held-out runs, and a long-running soak under real traffic.
   None of that exists, and no third-party evaluation has been run. See
   [STATUS.md](../status.md).

### 2.5 First Head-to-Head Against a Real WAF Product (Aegis Community v1.1.0)

On 2026-11-09 the engine was replayed against **Aegis Community Edition
v1.1.0**, a shipping WAF built on the Coraza engine with the bundled OWASP
CRS 4.25.1 LTS ruleset at paranoia level 1 in blocking mode, over real HTTP
on localhost using the same corpus files. This is the first measurement in
this repository against an actual product rather than a local stand-in.
Run manifest and per-case verdicts:
`benchmarks/real_comparative/results/aegis/` (`RUN.json`, `aegis_v10.jsonl`,
`aegis_crs.jsonl`).

| Corpus | SATGuardian | Aegis + CRS 4.25.1 PL1 |
| :--- | :---: | :---: |
| `crs_v430.jsonl` (4,050 vendor-authored attacks) | **82.0% recall** (3,322) | **80.7% recall** (3,268) |
| `heldout_v10.jsonl` (70 attacks) | 100% post-tuning diagnostic; frozen one-shot **38.6%** | **68.6% recall** (48/70) |
| `heldout_v10.jsonl` (44 controls) | 0.0% FPR post-tuning diagnostic; frozen one-shot **0.0%** | **36.4% FPR** (16/44) |
| `benign_heldout_v3_v10.jsonl` (665 pooled benign controls) | **0.5% FPR** (3/665; v10-only non-spent subset 0/44) | **22.9% FPR** (152/665) |

Union of both engines on `crs_v430` reaches **92.9% recall**; their
intersection is only **69.8%**. The engines miss different rule families
(e.g. SATGuardian 44/44 vs Aegis 7/44 on CRS rule 934140; Aegis 210/330 vs
SATGuardian 162/330 on rule 944300), so a cascade or ensemble is the natural
deployment shape — a product story a CRS-only vendor cannot copy. On benign
traffic the gap is sharper still: pooled over 665 benign controls, Aegis
blocked 152 (22.9% FPR) versus SATGuardian's 3 (0.5%; only the 44 v10 controls
are non-spent for SATGuardian).

Limits of the run: Aegis executed CRS 4.25.1 (the corpus targets 4.30),
paranoia level 1 only, community edition, plain HTTP, localhost, dummy
upstream, and its default rate limiter was disabled for isolation.
`latency_us` is not comparable across engines (full HTTP round-trip vs
in-process evaluation). One run, one configuration — not a product ranking.

---

## 3. Self-Hosted Deployment & the Security Units (SU) Review Model

The whole model in one sentence: **free, you get local protection on your own
node; paying, you get continuous review of new patterns, update proposals and
explanations — without ever giving up control of your WAF.**

- **No traffic hosting:** your DNS CNAMEs never point at SATGuardian servers. The Edge WAF runs where you put it — as a **standalone Rust binary**, a **reverse proxy** in front of Nginx/Apache/IIS, or an **Envoy sidecar** in Kubernetes talking `ext_authz` over a Unix Domain Socket (`/var/run/satguardian/waf.sock`).
- **Edge inspection carries no per-request fee:** the in-path plane is free and unlimited, needs no network access to enforce, and keeps working if the cloud is unreachable or the plan lapses.
- **What a paid plan buys is review, not control of your WAF:** the SATGuardian cloud synthesis service analyses the patterns your node recorded and returns update proposals with their equation, reduction and replay evidence. That service is metered in **Security Units (SU)** against the variables and minterms it compresses; when a plan's monthly SU quota is exhausted it returns `HTTP 402 SU_QUOTA_EXHAUSTED`, cloud review pauses, and the node keeps enforcing the clauses you already approved. The current plan table lives in the project README and on the product site; this paper does not restate prices, and no plan comes with an SLA or a coverage guarantee.
- **Control is the product feature:** cloud results land in your ledger as proposals (`dynamic_clauses.applied = 0`), never in the engine. Only `satguardian-waf clauses apply <id>` or an admin-token `POST /api/waf/clauses/{id}/apply` makes one enforce; `reject` discards a proposal and cannot remove a rule already in force; and `auto_sync_enabled` stays `false` until you turn it on.
