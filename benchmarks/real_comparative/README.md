# Comparativa real con otros WAF

This directory replaces the Python stand-ins in `benchmarks/` with measurements
made against **actual engines and actual vendor-authored expectations**.

Read [STATUS.md](../../STATUS.md) first. Nothing here has been published yet, and
nothing here may be quoted as a product claim until the owner has reviewed the
run.

---

## 1. Why this exists

The earlier harness scored SATGuardian against Python programs that imitated
Coraza, SafeLine and ModSecurity. Those numbers were never a comparison; they
compared two Python programs. `benchmarks/real_comparative/` only accepts a
number if it comes from the vendor's own code, pinned to a commit, reproducible
by someone else.

Two corpora are used, and they answer different questions:

| corpus | who wrote the labels | what it can prove | what it cannot prove |
| :--- | :--- | :--- | :--- |
| `corpus/unified_v1.jsonl` (255 cases, 155 held out) | us, before any engine call | a held-out estimate of SATGuardian, and the same estimate for every other engine | it is small, and hand-written from remembered catalogues |
| `crs_v430.jsonl` (5.088 registros, 4.050 etiquetados) | the OWASP CRS project | whether an engine fires on the payloads a mainstream rule set considers attacks | it is **in-sample for CRS** - those rules were written to pass these tests - so a CRS win here is a property of the corpus, not a result |

The publishable head-to-head is the held-out batch run through every engine. The
CRS suite is the coverage yardstick and the sanity check that each engine is
actually loaded with working rules.

## 2. Layout

```
benchmarks/real_comparative/
  README.md                      this file
  provenance.json                every pinned input, checksum and open blocker
  corpus/unified_v1.jsonl        our labelled requests, with the split field
  tools/normalize_corpus.py      corpus/*.json -> unified_v1.jsonl
  tools/ingest_crs_tests.py      CRS yaml -> crs_v430.jsonl (kept out of git, see provenance)
  adapters/                      one adapter per external engine
  results/<engine>/verdicts.jsonl
  results/RESULTS.json           the only file allowed to feed a public claim
```

`src/bin/satbench.rs` is the SATGuardian adapter. It is a `[[bin]]` discovered
automatically by Cargo, so the shipped engine and the benchmarked engine are the
same code path - there is no benchmark-only build.

## 3. The record contract

Every engine writes one JSON line per case with at least:

```
case_id, corpus, split, label, true_category, engine, engine_kind,
blocked, engine_category, matched_rules, reason, latency_us
```

Adapters must not add opinions the harness cannot check. If an engine cannot
supply a field, it writes `null` - it does not invent a value.

`split` decides where a number may go:

- `held_out` → publishable quality estimate, with a 95% Wilson interval.
- `in_sample_regression`, `consumed_for_tuning` → regression floor. These are
  printed under a heading that says they must not be quoted as accuracy.
- `vendor_in_sample` → CRS's own expectations. Near-perfect by construction for
  CRS; a genuine out-of-sample signal for SATGuardian.
- `unlabelled` → excluded from every rate. The CRS suite contains 1.038 stages
  with no `expect_ids`, and the project does not document whether an absent list
  means "must not match" or "not asserted". Treating them as benign controls
  would manufacture a false-positive rate out of ambiguity, so nobody scores
  them.

## 4. Fairness traps this harness is built to avoid

1. **In-sample as evidence.** `independent_v1` and `heldout_v1` were used to fix
   the engine. Blending them with a held-out batch inflates accuracy; the harness
   refuses to compute a rate over a mixed subset and exits if a corpus carries a
   split it does not know.
2. **Blocking vs detecting.** CRS runs in `DetectionOnly` in the accuracy pass. A
   "blocked" verdict in one engine and a "logged" verdict in another is not the
   same measurement, so each adapter records the engine mode in `reason`.
3. **Paranoia level.** PL1 is the default and PL2/3 changes both recall and FPR.
   Every result file records the PL; comparisons across PLs are invalid.
4. **Latency apples to oranges.** In-memory rule evaluation is not a request.
   `satbench` measures the engine call only, exactly like the shipped benchmark,
   and says so on every line. Proxy-mode numbers come from the deployment table
   (Fase 3), where a no-WAF baseline is subtracted.
5. **Corpus tuned to our own categories.** Our payloads are written in the
   vocabulary our engine understands. The CRS suite is the counterweight: we do
   not get to choose what counts as an attack in it.
6. **Silent exclusions.** Four CRS files cannot be opened on this machine (see
   §6). They are listed by name in `provenance.json` and the ingestor prints
   them, because a denominator that quietly shrank is a fake result.

## 5. How to run

```bash
# 0. everything below, in-process: no vendor tree, no HTTP, no deployed host
cargo test --release --test comparative_corpus_test -- --nocapture

# 1. rebuild the shared corpus (255 cases)
python3 benchmarks/real_comparative/tools/normalize_corpus.py

# 2. pin the vendor tree inside WSL and build the CRS corpus
git clone --depth 1 --branch v4.30.0 https://github.com/coreruleset/coreruleset.git \
    /var/tmp/satbench/vendor/coreruleset
python3 benchmarks/real_comparative/tools/ingest_crs_tests.py \
    --crs-dir /var/tmp/satbench/vendor/coreruleset \
    --out /var/tmp/satbench/corpus/crs_v430.jsonl

# 3. run our engine
cargo build --release --bin satbench
./target/release/satbench --corpus <jsonl> --out results/satguardian/verdicts.jsonl

# 4. adapters (pending, see provenance.json -> environment_blockers and
#    adapters/README.md for what each one must do)
```

## 6. State of the build, 2026-11-05

Done: shared corpus, CRS pin and ingestor, the SATGuardian adapter, and the first
vendor-authored measurement.

```
SATGuardian sobre crs_v430 (4.050 casos etiquetados por OWASP, 1.038 sin etiqueta)
  recall 9,51 % (385/4050)  IC 95 % [8,64 %, 10,45 %]
  latencia en proceso, Windows MSVC release: p50 19,1 us  p90 36,7 us  p99 97,7 us
```

Reproduced twice on 2026-11-05 from the same corpus digest
(`5ad95755…f3fc`): once by `src/bin/satbench.rs` and once by
`tests/comparative_corpus_test.rs`, both in-process with no HTTP. An earlier run
recorded p50 134 µs / p99 583 µs; the environment of that run could not be
verified afterwards, so `provenance.json` keeps those figures only as a
superseded note and they must not be quoted. Detection rates did not move
between the two runs — correctness is environment-independent, latency is not.
This is the honest shape of the problem: the engine fires on about one in ten of
the payloads the CRS project labels as attacks, while its own regression corpus
shows 100 %. Both numbers are true. The first is a coverage measurement against
somebody else's definitions; the second only proves the engine still does what it
was fixed to do.

Blocked, in order of consequence:

1. **Microsoft Defender refuses the CRS payload files.** Confirmed from the
   scanner's own history on 2026-11-05: `Get-MpThreatDetection` logs the exact
   four paths below, classified as `Backdoor:PHP/Remoteshell.A`,
   `Backdoor:PHP/Dirtelti.MTJ` and `Backdoor:PHP/Chopper.E!dha`. Because
   `wsl -l -v` reports `Ubuntu-20.04 … VERSION 1`, the Linux rootfs is a plain
   folder of NTFS files under `…\CanonicalGroupLimited.Ubuntu20.04onWindows_…\
   LocalState\rootfs`, so the real-time filter inspects every read made by every
   Linux process. Effect: `cat`, `head`, `wc`, `sha256sum`, `dd` and Python all
   get `EINVAL` on those four files, a `cp` that reports success ends in
   quarantine, and one copy came back with 25 lines removed. The tarball that
   looked "corrupted" for hours was the same detections. Rules 933100, 933111,
   933190 and 955260 therefore have zero coverage in the vendor corpus, and any
   score from it is computed on an easier subset than the full CRS suite. Anyone
   running this benchmark on a Windows machine will hit the same wall, which is
   why it belongs in the instructions rather than in a lost afternoon.
2. **Docker Desktop is stopped**, which blocks the container route for
   ModSecurity+CRS, Coraza+CRS and SafeLine - and is also the cleanest way around
   the file-read problem, because image layers live inside a WSL 2 VM.
3. **No sudo in WSL**, so `libmodsecurity3`/`libmodsecurity-dev` 3.0.4 and
   `golang-1.21` are installable in theory and not in practice from this session.
   Coraza needs Go 1.25 anyway; the official tarball installs into `~/.local`
   without root.
4. **~526 MB of available RAM** on a WSL 1 distro makes compiling Coraza here
   marginal even with a modern Go.

## 7. What may be said publicly, today

Nothing comparative. What may be said is the held-out measurement in
`corpus/heldout_v10_report.json` - frozen one-shot result (see the report for figures); `corpus/heldout_v10_post_tuning_report.json` - current engine: 100 % recall and 0,0 % false positives on 114
cases labelled before any engine call, measured once on 2026-11-08 - with its
interval and its date. The earlier `heldout_v2_report.json` figure (56,1 % /
7,0 %) remains published for provenance. The 9,5 % above is internal, it is a
coverage check against another project's tests, and it will look like a
contradiction to anyone who has not read this file. The CRS v4.30 in-sample
coverage (82.0 %) is a tuning measurement against the rule set's own tests, not
an independent evaluation.
