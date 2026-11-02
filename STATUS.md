# Project status and evidence

**Status: research prototype. Not a production-ready WAF.**

This file is the single source of truth for what has been measured. If another
document contradicts it, this file wins and the other document is stale.

## What is measured

| Claim | Evidence | Date |
|-------|----------|------|
| Rule-engine detections on the pinned regression corpus | `corpus/independent_v1.json`: 63/63 attacks, 0/16 benign blocked, 0 category mismatches | 2026-11-01 |
| Same, on a second batch built to vary the first | `corpus/heldout_v1.json`: 17/17 attacks, 0/4 benign blocked after fixes; the **first** run before fixes was 11/17 (64.71% recall) | 2026-11-01 |
| In-memory latency over the corpus | `satguardian-waf benchmark -r 10000`: tens of microseconds per payload, single-threaded, excluding network, TLS, proxy and upstream | 2026-11-01 |
| First-run baseline before the fix pass | `independent_v1`: 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) | 2026-11-01 |

`corpus/README.md` records how the corpus was assembled, why both files are now
in-sample, and the rules for adding cases.

## What is not measured

- **No independent or third-party evaluation.** The corpus is hand-written in
  this repository. There is no held-out estimate after the second fix pass.
- **No comparison against real WAF products.** The Python harness
  (`run_benchmark.py`) runs local stand-ins written for this repository. Rows
  named Coraza, SafeLine, ModSecurity or "probabilistic NLP" are reimplementations,
  not those products. They must never be cited as vendor benchmarks.
- **No production soak.** No staged rollout, no traffic replay at scale, no
  long-running memory or rule-update testing.
- **No TLS or WebSocket handling in the standalone proxy.** TLS terminates in
  front of it; WebSocket upgrades are rejected.
- **No ESP32/embedded port.** Embedded deployment is a research direction only.
- **Prebuilt artifacts under `dist/` and `releases/` are stale.** They were built
  before the claims were corrected and still contain the old banner text. Rebuild
  or delete them before publishing; do not ship them as current.

## How to reproduce

```bash
# Detection regression (both corpora)
cargo test --test independent_corpus_test -- --nocapture

# Full Rust suite
cargo test

# In-memory benchmark over the corpus
cargo run --release -- benchmark -r 10000

# Python reference harness (local stand-ins, in-sample)
python run_benchmark.py 1000
```

## Why this file exists

Earlier versions of this repository published a benchmark that:

- capped perfect accuracy at 99.9% and floored zero error rates at 0.1%;
- labelled Python regex stand-ins as "Coraza WAF (OWASP CRS v4)" and
  "SafeLine WAF (Chaitin T1K)";
- derived "3.38x faster", "15.0x faster" and "reduced false negatives by N
  percentage points" headlines from those stand-ins;
- presented the numbers as production evidence.

Those claims were fabricated or misleading. The cap/floor logic is gone, the
stand-ins are labelled, and the Rust benchmark now refuses to run without the
versioned corpus. The guardrail tests in `tests/docs_claims_test.rs` fail the
build if the banned claims or unlabelled comparisons return.

Treat a green test suite as "no known regressions on pinned inputs", not as
"safe for production".
