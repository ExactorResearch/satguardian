# Proof of Concept (PoC) Guide: SATGuardian Edge WAF

This guide provides step-by-step instructions to run and test the **SATGuardian
Edge WAF** (`satguardian`) locally using the Rust binary and the Python benchmark
and advisor suite.

> **Status: SATGuardian Edge WAF v0.3.0.** The PoC measures in-memory rule evaluation on a
> small in-sample corpus plus one held-out run of hand-written payloads. It is
> not a production validation and there is no third-party evaluation. See
> [STATUS.md](../status.md).

---

## 1. What This PoC Demonstrates

1. **Deterministic Lexical & Bitmask Inspection:** How HTTP requests are decoded
   across multiple obfuscation layers, mapped to a 128-bit `FeatureVector`
   (`u128`), and evaluated via bitwise `AND` operations
   (`(fv.bits & required_mask) == expected_bits`) with causal rule traces.
2. **Python stand-in harness:** CPU timing and detection on the in-repo payload
   list, comparing the Python reference port against local reimplementations.
   It does not execute Coraza, SafeLine, ModSecurity or a trained model.
3. **Offline rule proposals and replay:** How `satguardian-advisor.py` mines
   `waf_ledger.db`, replays candidate rules against recorded benign traffic to
   find collisions, and writes evidence-backed audit reports
   (`audit_report.html`, `audit_report.md`).
4. **The approval gate:** How a cloud review run leaves its results as proposals
   (`dynamic_clauses.applied = 0`) that enforce only after you approve them:
   `satguardian-waf clauses list`, `clauses apply <id>`, `clauses reject <id>`.
   The minimization that produced a proposal happens on the SATGuardian cloud
   service (`satguardian.tech`) and is not part of this repository.

---

## 2. Running the Native Rust Benchmark

The benchmark reads `corpus/independent_v1.json`. Build and run:

```powershell
cargo run --release -- benchmark -r 10000
```

### Example output (one run on this machine; rerun to reproduce)

```text
SATGuardian Edge WAF: In-Memory Engine Benchmark
   Corpus        : corpus/independent_v1.json (independent-v1)
   Cases         : 79 (63 labelled attacks, 16 benign)
   Requests      : 10000 (corpus cycled)
   Scope: in-memory rule evaluation only. No network, proxy,
   TLS, upstream or stateful tracking is included.
   Accuracy is in-sample regression, not a held-out estimate.

Detection on the labelled corpus (in-sample regression):
   True positives       : 63 / 63
   False negatives      : 0
   True negatives       : 16 / 16
   False positives      : 0

Latency distribution (microseconds, in-memory only):
   Min                  :      11.90 µs
   Average              :     936.73 µs
   p50 (median)         :     458.10 µs
   p90                  :    2626.10 µs
   p99                  :    6006.90 µs
   Max                  :   11449.70 µs
   Throughput           :   44491.88 req/sec (single thread)
```

---

## 3. Running the Python Stand-In Harness (`run_benchmark.py`)

```powershell
python run_benchmark.py 1000
```

### Example results (1,000 sampled requests, 50% attacks)

Only the SATGuardian row is this project's code. All other rows are local Python
stand-ins, not the named products.

| Agent (Python, in-process) | Accuracy (in-sample) | Avg CPU time | P99 CPU time | FPR | FNR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| SATGuardian reference port | 100.0% | `0.0586 ms` | `0.2267 ms` | 0.0% | 0.0% |
| CRS-style stand-in (not Coraza) | 97.3% | `0.2350 ms` | `0.5244 ms` | 0.0% | 5.4% |
| Semantic-token stand-in (not SafeLine) | 94.4% | `0.0637 ms` | `0.1618 ms` | 0.0% | 11.2% |
| Probabilistic token stand-in (heuristic) | 77.3% | `0.0726 ms` | `0.1708 ms` | 24.6% | 20.8% |
| Unnormalized regex stand-in (not ModSecurity) | 76.5% | `0.0383 ms` | `0.0792 ms` | 0.0% | 47.0% |

### What the numbers do and do not show

- The Rust engine's in-memory evaluation is hundreds of microseconds per payload.
  That excludes network and proxy overhead and says nothing about end-to-end
  throughput.
- Detection on the pinned corpus is 100%/0% only because the same cases were
  used to drive the fixes; those rows are in-sample regression floors.
  First-run baselines were 80.95% recall / 18.75% FPR (`independent_v1`) and
  64.71% recall / 0% FPR (`heldout_v1`). The only out-of-sample run is
  `benchmarks/real_comparative/corpus/heldout_v10.jsonl`, executed once on
  2026-11-08: the frozen one-shot estimate is **38.6% recall** on 70 attacks
  (95% CI 28.0–50.3%) and **0.0% false-positive rate** on 44 controls (95% CI
  0.0–8.0%); the current engine measures **100%/0.0%** on the same batch as a
  post-tuning diagnostic. The earlier `corpus/heldout_v2.json` figure
  (56.1%/7.0%) remains for provenance. See [corpus/README.md](../corpus.md).
- The harness does not show that SATGuardian is faster or more accurate than a
  real vendor WAF. That comparison has not been run, and no part of this PoC has
  been evaluated by a third party.

---

## 4. Generating the Forensic Audit Reports (`satguardian-advisor.py`)

To analyze the 3,799 recorded transactions in `waf_ledger.db`, verify candidate
rules against the Digital Twin replay of recorded benign traffic, and generate
HTML and Markdown evidence-backed audit reports:

```powershell
python satguardian-advisor.py --report audit_report.html
python satguardian-advisor.py --report-md audit_report.md
```

### Summary of the bundled `waf_ledger.db` (demo data)
- **Total recorded requests:** `3,799`
- **Blocked:** `2,136` (`951` SQLi, `477` XSS, `472` path traversal, `234` rate-limit bursts, `2` SSRF)
- **Allowed benign:** `1,663`
- **Pending novel anomalies:** reported by the advisor for the current ledger snapshot

These counts describe the demo ledger, not a customer tenant and not
independently labelled ground truth.

---

## 5. Interactive Streamlit Dashboard (`app.py`)

To explore the interactive payload inspector, LaTeX causal deduction traces, and live benchmark runner in your browser:

```powershell
streamlit run app.py
```
