# Project status and evidence

**Status: SATGuardian Edge WAF v0.3.0.**

This file is the single source of truth for what has been measured. If another
document contradicts it, this file wins and the other document is stale.

## What is measured

| Claim | Evidence | Date |
|-------|----------|------|
| Rule-engine detections on the pinned regression corpus | `corpus/independent_v1.json`: 63/63 attacks, 0/16 benign blocked, 0 category mismatches | 2026-11-01 |
| Same, on a second batch built to vary the first | `corpus/heldout_v1.json`: 17/17 attacks, 0/4 benign blocked after fixes; the **first** run before fixes was 11/17 (64.71% recall) | 2026-11-01 |
| In-memory latency over the corpus | `satguardian-waf benchmark -r 10000`: tens of microseconds per payload, single-threaded, excluding network, TLS, proxy and upstream | 2026-11-01 |
| First-run baseline before the fix pass | `independent_v1`: 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) | 2026-11-01 |
| **Current engine on the held-out batch** | `benchmarks/real_comparative/corpus/heldout_v10.jsonl`, measured today: **70/70 attacks detected (100% recall, 95% CI 94.8–100%)**, 0/44 controls blocked (**0.0% FPR**, 95% CI 0.0–8.0%). Report: `corpus/heldout_v10_post_tuning_report.json` — post-tuning diagnostic, not an estimate | 2026-11-08 |
| **Frozen one-shot estimate** | Same batch, run once before any fix against it: 27/70 attacks detected (**38.6% recall**, 95% CI 28.0–50.3%), 0/44 controls blocked (**0.0% FPR**, 95% CI 0.0–8.0%). Report: `corpus/heldout_v10_report.json` — frozen, never rewritten | 2026-11-08 |
| Coverage against the OWASP CRS v4.30 attack suite (vendor-authored, in-sample for CRS) | `benchmarks/real_comparative/corpus/crs_v430.jsonl`: 3,322/4,050 labelled attacks detected (**82.0% recall**); `satbench` in-process, p50 ~5.0 ms on 2026-11-09 hardware (payload-size dependent; an earlier note recorded ~0.7 ms), excluding network/TLS/proxy | 2026-11-08 → 2026-11-09 |
| **Benign-traffic false-positive measurement (665 pooled controls)** | `benchmarks/real_comparative/corpus/benign_heldout_v3_v10.jsonl` — all `label: benign` cases from held-out batches v3–v10, run 2026-11-09 through both engines. **SATGuardian: 3/665 blocked = 0.5% FPR** (95% CI 0.2–1.3%; v10-only non-spent subset 0/44 — v3–v9 benign controls were tuning inputs, so the pooled figure is partly in-sample). **Aegis + CRS 4.25.1 PL1: 152/665 blocked = 22.9% FPR** (95% CI 19.8–26.2%, consistent across every batch: 8–32 blocks per ~50–164 controls). Verdicts: `results/aegis/aegis_benign.jsonl`, `results/satguardian/sat_benign.jsonl` | 2026-11-09 |
| **First head-to-head vs a real WAF product** | Aegis Community Edition v1.1.0 (Coraza engine + bundled OWASP CRS 4.25.1 LTS, paranoia level 1, blocking mode) replayed over real HTTP on localhost, 2026-11-09. On `crs_v430.jsonl`: **Aegis 3,268/4,050 (80.7% recall) vs SATGuardian 3,322/4,050 (82.0%)**; union of both engines 3,764/4,050 (**92.9%**), intersection 2,826 (**69.8%**) — coverage is strongly complementary. On `heldout_v10.jsonl`: Aegis 48/70 recall (**68.6%**) and 16/44 benign blocked (**36.4% FPR**); SATGuardian current engine 70/70 and 0/44 (post-tuning diagnostic — the frozen one-shot estimate stays 38.6%/0.0%). Verdicts and run manifest: `benchmarks/real_comparative/results/aegis/` (`RUN.json`, `aegis_v10.jsonl`, `aegis_crs.jsonl`); replay adapter `tmp/aegis_replay.py` pending promotion to `adapters/`. Caveats: Aegis ran CRS 4.25.1 not 4.30, paranoia level 1 only, community edition, plain HTTP, traffic-control rate limit disabled for isolation, dummy upstream; latency columns are not comparable (Aegis = full HTTP round-trip, SATGuardian = in-process) | 2026-11-09 |
| Superseded held-out batches | `heldout_v2` (56.1%/7.0%), `heldout_v3`–`heldout_v9` were each measured once and are now tuning inputs; their reports remain for provenance. `heldout_v8` measured 77.5%/4.2% and `heldout_v9` 50.0%/6.4% before being spent. `heldout_v10` was measured once (38.6%/0.0%), then spent by the protocol/DSL tuning pass — its one-shot report stays frozen and `heldout_v10_post_tuning_report.json` records current behaviour (100%/0.0% diagnostic, not an estimate). Post-repair diagnostics on the spent batches (not estimates): v6 99.0%/0.0%, v7 92.1%/0.0%, v8 100%/0.0%, v9 97.7%/4.3% (two historical `union select`-in-prose FPs), v10 100%/0.0% | 2026-11-01 → 2026-11-08 |

`corpus/README.md` records how each batch was assembled, why the first two are
now in-sample, and the rules for adding cases.

## What is not measured

- **No independent or third-party evaluation.** Every batch, including the
  held-out one, is hand-written in this repository by the same author as the
  engine. `heldout_v10` was a real out-of-sample estimate of *those* payloads;
  its one-shot 38.6% recall / 0.0% FPR is frozen in `heldout_v10_report.json`,
  while the current engine measures 100%/0.0% on the same batch
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
| `../target/release/satbench.exe --corpus benchmarks/real_comparative/corpus/heldout_v10.jsonl` | `heldout_v10.jsonl` (70 attacks, 44 benign) | 44 | one-shot: **38.6% recall, 0.0% FPR** (`corpus/heldout_v10_report.json`); current engine: **100%/0.0%** post-tuning diagnostic (`corpus/heldout_v10_post_tuning_report.json`) | current behaviour is the post-tuning diagnostic; the frozen one-shot estimate stays 38.6%/0.0% |
| `cargo run --release --bin satbench -- --corpus benchmarks/real_comparative/corpus/unified_v1.jsonl` | `unified_v1.jsonl` floors | — | 100% recall, 0.0% FPR on in-sample splits | regression floor, not an estimate |

So the **0.0% false-positive rate on 44 controls** above is the held-out
measurement. `tests/comparative_corpus_test.rs::heldout_v10_reproduction_matches_the_published_report`
re-derives it in-process. Batch v10 has since been spent by the protocol/DSL
detector iteration: the engine now clears all 70 attacks, so the test asserts
the one-shot figures remain intact as provenance *and* that live behaviour
still matches `corpus/heldout_v10_post_tuning_report.json` — if the engine
ever blocks a different set of v10 cases, the test fails. Per maintainer
decision no `heldout_v11` will be produced; the 38.6%/0.0% one-shot remains
the only publishable held-out estimate. `tests/heldout_v2_measurement_test.rs`
is gated behind an environment variable and now documents a spent batch.

`tests/comparative_corpus_test.rs` calls the engine in-process — no HTTP, no
proxy, no deployed host — and pins all three numbers as unit tests. Its held-out
test asserts the *reproduction*, not the quality: if the engine ever blocks a
different set of held-out cases, the test fails and says the batch is spent,
which is the only way a held-out estimate can stay trustworthy.

```bash
# The frozen one-shot estimate lives in corpus/heldout_v10_report.json
# (38.6% recall / 0.0% FPR). Re-running the corpus now prints the current
# engine behaviour (100%/0.0%) recorded in
# corpus/heldout_v10_post_tuning_report.json.
../target/release/satbench.exe --corpus benchmarks/real_comparative/corpus/heldout_v10.jsonl \
    --out benchmarks/real_comparative/results/satguardian/verdicts_heldout_v10_post_tuning.jsonl

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
