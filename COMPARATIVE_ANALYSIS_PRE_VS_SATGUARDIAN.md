# Comparative Architecture Notes: SATGuardian and Local Stand-Ins

**Subject:** how SATGuardian differs from signature, anomaly-scoring, semantic and
probabilistic WAF designs, and what the repository actually measures  
**Target system:** `satguardian` v0.3.0

> **Status: research prototype.** This is not a vendor benchmark. The Python
> harness runs local reimplementations of each technique, not Coraza, SafeLine,
> ModSecurity or a trained NLP model. Detection numbers are in-sample on a
> hand-written corpus. See [STATUS.md](STATUS.md) and
> [corpus/README.md](corpus/README.md).

---

## 1. What is being compared

1. **SATGuardian:** multi-pass lexical normalization (`src/ast/lexer.rs`), a
   128-bit feature bitmask (`FeatureVector`), and bitwise rule evaluation in
   `src/engine/sat_solver.rs`, plus out-of-band EXACTOR GXOR minimization over
   `{AND, OR, NOT, XOR}` up to 128 variables.
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
| Detection | 63/63 attacks, 0/16 benign blocked (in-sample regression) |
| Min latency | `11.9 µs` |
| p50 | `19.8 µs` |
| Mean | `21.6 µs` |
| p90 | `29.1 µs` |
| p99 | `49.3 µs` (near the 50 µs target; varies with load) |
| Max | `311.1 µs` |
| Single-thread throughput | `44,492 req/sec` |

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
controls. Sixteen controls cannot support a general false-positive claim.

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
tenant. Regenerate the audit with:

```bash
python satguardian-advisor.py --report-md audit_report.md
```
