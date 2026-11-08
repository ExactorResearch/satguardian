# Comparative Architecture Notes: SATGuardian and Local Stand-Ins

**Subject:** how SATGuardian differs from signature, anomaly-scoring, semantic and
probabilistic WAF designs, and what the repository actually measures  
**Target system:** `satguardian` v0.3.0

> **Status: research prototype.** This is not a vendor benchmark. The Python
> harness runs local reimplementations of each technique, not Coraza, SafeLine,
> ModSecurity or a trained NLP model. Detection numbers below are in-sample
> regression floors on a hand-written corpus, except the single held-out run
> called out separately. There is no third-party evaluation. See
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
| Min latency | `11.9 µs` |
| p50 | `19.8 µs` |
| Mean | `21.6 µs` |
| p90 | `29.1 µs` |
| p99 | `49.3 µs` (near the 50 µs target; varies with load) |
| Max | `311.1 µs` |
| Single-thread throughput | `44,492 req/sec` |

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
| Recall on 70 attacks | frozen one-shot **38.6%** (27/70), 95% CI 28.0–50.3%; current engine **100%** (70/70) post-tuning diagnostic |
| False-positive rate on 44 controls | **0.0%** (0/44), 95% CI 0.0–8.0% |

The batch is hand-written from public payload catalogues and its benign controls
are imagined traffic, not a customer access log, so this measures those payloads
and nothing wider. No third-party evaluation exists, and `corpus/README.md`
records that tuning against this batch would invalidate it.

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
