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
| **Held-out estimate — the only one that exists** | `corpus/heldout_v2.json` in one run before any fix: 55/98 attacks detected (**56.1% recall**, 95% CI 46.3–65.5%), 4/57 controls blocked (**7.0% FPR**, 95% CI 2.8–16.7%). Report: `corpus/heldout_v2_report.json` | 2026-11-04 |

`corpus/README.md` records how each batch was assembled, why the first two are
now in-sample, and the rules for adding cases.

## What is not measured

- **No independent or third-party evaluation.** Every batch, including the
  held-out one, is hand-written in this repository by the same author as the
  engine. `heldout_v2` is a real out-of-sample estimate of *those* payloads —
  its 56.1% recall and 7.0% false-positive rate are the honest numbers to quote,
  and the in-sample 100%/0% rows above are not. Neither number says anything
  about traffic that was not imagined: no customer access log has ever been
  measured against this engine.
- **No comparison against real WAF products.** The Python harness
  (`run_benchmark.py`) runs local stand-ins written for this repository. Rows
  named Coraza, SafeLine, ModSecurity or "probabilistic NLP" are reimplementations,
  not those products. They must never be cited as vendor benchmarks.
- **No production soak.** No staged rollout, no traffic replay at scale, no
  long-running memory or rule-update testing.
- **No TLS or WebSocket handling in the standalone proxy.** TLS terminates in
  front of it; WebSocket upgrades are rejected.
- **Prebuilt artifacts under `dist/` and `releases/` are stale.** They were built
  before the claims were corrected and still contain the old banner text. Rebuild
  or delete them before publishing; do not ship them as current.

## How to reproduce

Two different numbers get quoted in these documents and they come from two
different corpora. Do not expect one command to print the other one:

| what you run | corpus | benign controls | what it prints | status of that corpus |
| :--- | :--- | :---: | :--- | :--- |
| `cargo run --release -- benchmark -r 10000` | `corpus/independent_v1.json` | 16 | 100% recall, **0.0% FPR** | in-sample regression floor: every miss in it was used to fix the engine |
| `cargo run --release --bin satbench -- --corpus benchmarks/real_comparative/corpus/unified_v1.jsonl` | `corpus/heldout_v2.json` (plus the two floors, reported separately) | 57 | **56.1% recall, 7.0% FPR** in the `HELD-OUT` block | the only held-out estimate; publishable |

So the **7.0% false-positive rate on 57 controls** in the table above is the
held-out measurement, and the `benchmark` subcommand cannot reproduce it — it
does not load `heldout_v2.json`. Re-running the held-out batch read-only
reproduces 55/98 and 4/57 exactly (checked 2026-11-05 with both commands); what
spends the batch is fixing the engine against its misses, which is why
`tests/heldout_v2_measurement_test.rs` is gated behind an environment variable.

`tests/comparative_corpus_test.rs` calls the engine in-process — no HTTP, no
proxy, no deployed host — and pins all three numbers as unit tests. Its held-out
test asserts the *reproduction*, not the quality: if the engine ever blocks a
different set of held-out cases, the test fails and says the batch is spent,
which is the only way a held-out estimate can stay trustworthy.

```bash
# Held-out estimate (56.1% recall / 7.0% FPR on 57 controls)
python3 benchmarks/real_comparative/tools/normalize_corpus.py
cargo run --release --bin satbench -- \
    --corpus benchmarks/real_comparative/corpus/unified_v1.jsonl

# Detection regression (both in-sample corpora)
cargo test --test independent_corpus_test -- --nocapture

# The same measurements as in-process unit tests: no HTTP, no proxy, no deployed host
cargo test --test comparative_corpus_test -- --nocapture

# Full Rust suite
cargo test

# In-memory benchmark over the in-sample corpus
cargo run --release -- benchmark -r 10000

# Python reference harness (local stand-ins, in-sample)
python run_benchmark.py 1000
```

## Control boundary (what the paid tier actually does)

The product promise is: free, local protection; paid, ongoing review, update
proposals and explanations — without giving up control of the WAF. As of
2026-11-04 the code matches that:

- `auto_sync_enabled` defaults to `false` (`src/config.rs`), and the shipped
  `waf_config.toml` leaves it off. Cloud review runs only if you turn it on or
  invoke `satguardian-waf sync-simplify` / `POST /api/waf/sync-simplify`.
- A review uploads recorded `u128` feature vectors, not raw requests, and what
  comes back is stored in `dynamic_clauses` with `applied = 0`. Startup loads
  `applied = 1` rows only.
- A clause enters the engine after an explicit approval
  (`satguardian-waf clauses apply <id>`, or `POST /api/waf/clauses/{id}/apply`
  behind the admin token). `reject` deletes only unapplied proposals. Approved
  clauses are registered in an `RwLock`-guarded table capped at 4,096; there is
  no lock-free swap and no automatic apply anywhere in the client.
- The Boolean minimizer (`exactor-core-v128`) is not a dependency of this crate
  and is not in any client artefact; minimization happens on the service side.
- `satguardian-advisor.py` has no batch-approval option. Every proposal is
  decided one at a time by the operator running it.

`tests/docs_claims_test.rs::cloud_review_stays_opt_in_and_never_applies_by_itself`
and `tests/clause_approval_test.rs` fail if any of that regresses.

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
