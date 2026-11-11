# Comparative Architecture Notes: SATGuardian and Local Stand-Ins

**Subject:** how SATGuardian differs from signature, anomaly-scoring, semantic and
probabilistic WAF designs, and what the repository actually measures  
**Target system:** `satguardian` v0.3.0

> **Status: SATGuardian Edge WAF v0.3.0.** The Python
> harness runs local reimplementations of each technique, not Coraza, SafeLine,
> ModSecurity or a trained NLP model. Detection numbers below are in-sample
> regression floors on a hand-written corpus, except the single held-out run
> called out separately. The only real-product measurement is the 2026-11-09
> head-to-head against Aegis Community Edition v1.1.0 in §2.5; there is still
> no third-party evaluation. See
> [STATUS.md](STATUS.md) and [corpus/README.md](corpus/README.md).

---

## 1. What is being compared

1. **SATGuardian:** multi-pass lexical normalization (`src/ast/lexer.rs`), a
   128-bit feature bitmask (`FeatureVector`), and bitwise rule evaluation in
   `src/engine/sat_solver.rs`. Rule review is a separate, opt-in step: the
   client can send recorded minterms to the **SATGuardian cloud synthesis**
   service (`satguardian.tech`), which minimizes them server-side and returns
   compiled clauses. The minimizer is not part of this repository and is not
   distributed to customers; the client stores what comes back as proposals that
   an operator must approve before anything enforces.
2. **CRS-style stand-in (not Coraza):** a few hand-written regex rules with a
   simple anomaly score over decoded request targets. It does not model the real
   CRS rule count, paranoia levels or exclusions.
3. **Semantic-token stand-in (not SafeLine):** single-pass decode plus a small
   pattern list. It is not Chaitin's engine.
4. **Probabilistic token stand-in (not a trained model):** fixed keyword weights
   and Shannon entropy. It is not a trained classifier.
5. **Unnormalized regex stand-in (not ModSecurity):** deliberately naive
   signatures over raw fields.

The point of the harness is to regression-test the Python reference port and to
illustrate design trade-offs. It cannot rank real products.

---

## 2. What the harness measures

`python run_benchmark.py 1000` samples the in-repo payload list (1,000 requests,
50% attacks by default). Only the SATGuardian row is this project's code.

| Agent (Python, in-process) | Accuracy (in-sample) | Avg CPU time | P99 CPU time | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| SATGuardian reference port | 100.0% | `0.0586 ms` | `0.2267 ms` | 0.0% | 0.0% |
| CRS-style stand-in (not Coraza) | 97.3% | `0.2350 ms` | `0.5244 ms` | 0.0% | 5.4% |
| Semantic-token stand-in (not SafeLine) | 94.4% | `0.0637 ms` | `0.1618 ms` | 0.0% | 11.2% |
| Probabilistic token stand-in (heuristic) | 77.3% | `0.0726 ms` | `0.1708 ms` | 24.6% | 20.8% |
| Unnormalized regex stand-in (not ModSecurity) | 76.5% | `0.0383 ms` | `0.0792 ms` | 0.0% | 47.0% |

Values are from one run on 2026-11-01 and move slightly between runs. Reproduce
with `python run_benchmark.py 1000`.

### 2.1 Native Rust engine on the pinned corpus

`satguardian-waf benchmark -r 10000` (in-memory rule evaluation only; no TLS,
proxy hop or upstream):

| Metric | Representative run |
| :--- | :--- |
| Corpus | `corpus/independent_v1.json` (63 attacks, 16 benign) |
| Detection | 63/63 attacks, 0/16 benign blocked (**in-sample regression floor**) |
| First run before fixes | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Min latency | `70.0 µs` |
| p50 | `~458 µs` |
| Mean | `~937 µs` |
| p90 | `~2.6 ms` |
| p99 | `~6.0 ms` |
| Max | `~11.4 ms` |
| Single-thread throughput | `~1,063 req/sec` |

All of those latencies are **in-memory only**: they exclude TLS, the proxy hop,
the upstream service and SQLite ledger writes, and they were taken on this
project's own machine.

### 2.2 The one held-out measurement

The 100%/0% rows above describe cases that were used to drive the fixes. The
only out-of-sample measurement in this repository comes from
`benchmarks/real_comparative/corpus/heldout_v10.jsonl` (70 attacks, 44 benign
controls), run once on 2026-11-08 before tuning (the earlier `corpus/heldout_v2.json`,
98 attacks and 57 controls, was measured once on
2026-11-04):

| Metric | Held-out result |
| :--- | :--- |
| Recall on 70 attacks | frozen one-shot (27/70); current engine **100%** (70/70) post-tuning diagnostic |
| False-positive rate on 44 controls | **0.0%** (0/44), 95% CI 0.0–8.0% |

The batch is hand-written from public payload catalogues and its benign controls
are imagined traffic, not a customer access log, so this measures those payloads
and nothing wider. No third-party evaluation exists, and `corpus/README.md`
records that tuning against this batch would invalidate it.

### 2.5 The first real-product head-to-head (Aegis Community v1.1.0)

On 2026-11-09 SATGuardian was replayed against **Aegis Community Edition
v1.1.0** — a shipping WAF built on the Coraza engine with the bundled OWASP
CRS 4.25.1 LTS ruleset at paranoia level 1, blocking mode — over real HTTP on
localhost, on the same corpus files. This is the first measurement in this
repository against an actual product; earlier competitor rows remain local
stand-ins. Artifacts: `benchmarks/real_comparative/results/aegis/`
(`RUN.json`, `aegis_v10.jsonl`, `aegis_crs.jsonl`).

| Corpus | SATGuardian | Aegis + CRS 4.25.1 PL1 |
| :--- | :---: | :---: |
| `crs_v430.jsonl` attacks | **82.0%** (3,321/4,050) | **80.7%** (3,268/4,050) |
| `heldout_v10.jsonl` attacks | 100% post-tuning diagnostic; frozen one-shot | **68.6%** (48/70) |
| `heldout_v10.jsonl` controls | 0.0% FPR post-tuning diagnostic; frozen one-shot **0.0%** | **36.4%** (16/44) |
| `benign_heldout_v3_v10.jsonl` (665 pooled benign controls) | **0.5%** (3/665; v10-only non-spent subset 0/44) | **22.9%** (152/665) |

Union of both engines on `crs_v430`: **92.9%** recall; intersection: **69.8%**.
The engines miss different rule families — e.g. SATGuardian detects 44/44 vs
Aegis 7/44 on CRS rule 934140, while Aegis detects 210/330 vs SATGuardian
162/330 on rule 944300 — so a cascade is the natural deployment shape.

Limits: Aegis ran CRS 4.25.1 (the corpus targets 4.30), paranoia level 1,
community edition, plain HTTP, localhost, dummy upstream, default rate
limiter disabled. Latency is not comparable across the two rows (full HTTP
round-trip vs in-process evaluation). One run, one configuration — not a
product ranking.

The false-positive gap is the sharpest measured difference: pooled over all
665 benign controls from batches v3–v10, Aegis blocked 152 (**22.9% FPR**,
95% CI 19.8–26.2%) while SATGuardian blocked 3 (**0.5%**, CI 0.2–1.3%). For
SATGuardian only the 44 v10 controls are non-spent (v3–v9 benign controls
were tuning inputs); for Aegis every control was fresh. The controls are
imagined traffic authored inside this project, not a customer access log, so
the absolute rates describe these payloads — but the ~45× gap between engines
on identical inputs is the measured fact.

---

## 3. Engineering observations

### 3.1 Anomaly scoring
Anomaly scoring transforms several request targets and evaluates many rules. That
buys coverage and configurability at a per-request CPU cost. The local stand-in
implements only a small approximation (`20` regex rules), so its latency is not a
measurement of real CRS cost. SATGuardian instead normalizes once and evaluates
bitmasks; whether that trade-off holds against a real deployment is untested.

### 3.2 Semantic tokenization
Single-pass decoding plus token patterns is cheap, but it can miss nested
encodings. The stand-in misses `11.2%` of the in-repo attacks, largely on
double-encoded traversal. SATGuardian decodes multiple layers; on the pinned
corpus it catches those cases after the 2026-11-01 fixes. The corpus was used to
drive those fixes, so this is not held-out evidence.

### 3.3 Probabilistic token scoring
Fixed token weights misfire on benign technical prose. The local heuristic blocks
`24.6%` of the benign controls in the in-repo stream. SATGuardian requires
structural conjunctions, and produced no false positives on the 16 benign corpus
controls — an in-sample regression floor on sixteen cases. The single held-out
batch is the relevant comparison: it measured a **0.0% false-positive rate on 44
controls** (95% CI 2.8–16.7%), which is what the design actually costs on
payloads that were not used for tuning.

### 3.4 Unnormalized regex
Raw signature scanning is the cheapest row in the harness and the leakiest on
obfuscated payloads (`47.0%` FNR in this stream). This illustrates why
normalization matters; it does not measure ModSecurity.

---

## 4. Demonstration Ledger (`waf_ledger.db`)

The bundled SQLite ledger is demo data used to exercise the advisor pipeline:
`3,799` transactions (`2,136` blocked, `1,663` allowed). Advisor candidates are
replayed against the benign rows and collision counts are printed per run. The
ledger is not independent evidence of detection quality and is not a customer
tenant. Minterms the engine did not recognize sit in `novel_anomalies` as
**patterns awaiting analysis** — they are review candidates, not unprotected
threats — and cloud review is off unless `auto_sync_enabled` is turned on.
Whatever the service returns is stored as a proposal (`dynamic_clauses.applied
= 0`) and only enforces after `satguardian-waf clauses apply <id>`. Regenerate
the audit with:

```bash
python satguardian-advisor.py --report-md audit_report.md
```
