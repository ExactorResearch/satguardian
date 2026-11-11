# Detection corpus and measurement protocol

This directory contains hand-labelled HTTP requests used by
`tests/independent_corpus_test.rs`. The corpus is small and hand-written on
purpose: it exists to make regressions visible, not to certify real-world
accuracy.

## Files

| File | Contents | Status |
|------|----------|--------|
| `independent_v1.json` | 63 attacks + 16 benign controls across SQLi, XSS, RCE, LFI, SSRF, GraphQL, prototype pollution, JWT, framework exploits, WordPress and file exposure. | Regression suite after the 2026-11-01 fix pass. |
| `heldout_v1.json` | 17 attack variants + 4 benign controls written after the first fix pass. | Measured once before correction, then kept as a regression suite. |
| `heldout_v2.json` | 98 attacks + 57 benign controls written on 2026-11-04, deliberately using techniques absent from the two files above, plus six attack families the engine has no name for (NoSQL, XXE, SSTI, response splitting, Host header, upload). | Held out at the moment of writing. `heldout_v2_report.json` is its single measurement. |

Payload provenance is recorded per case in the `note` field and in the
`provenance` block: OWASP CRS/WSTG notes, PortSwigger filter-evasion notes,
Log4Shell obfuscation catalogues, RFC 7519 JWT fixtures, and benign snippets
modelled on framework/CDN documentation.

`heldout_v2.json` adds a constraint the earlier batches did not state: the
payloads were hand-written from catalogues the author recalled rather than
copied from a fetched file, so each note names the documented technique instead
of a URL, and the benign set is imagined traffic — not a sample from a
customer's access log. The first run is produced by
`tests/heldout_v2_measurement_test.rs`, which asserts nothing about detection
quality on purpose: a held-out estimate that fails into a fix and is then
re-measured is not an estimate.

## Measurements

All numbers below come from `SatguardianSatEngine::new()` with the default
configuration and the corpus request as the only input. No network hop, no
upstream, no stateful verdict.

### First run, before any fix (2026-11-01)

`independent_v1.json`:

| Metric | Value |
|--------|-------|
| Attacks | 63 |
| Benign | 16 |
| True positives | 51 |
| False negatives | 12 |
| False positives | 3 |
| Recall | 80.95% |
| False-positive rate | 18.75% |

Missed attacks: MySQL executable comments hiding `UNION`/`OR`
(`/*!50000...*/`), `||` tautologies, HTML-entity `javascript:` schemes,
Java `ProcessBuilder`, encoded PowerShell, overlong UTF-8 traversal,
`\u`-escaped `__proto__`, and nested `${lower:...}` Log4Shell lookups.

False positives: a local `<script src="/static/app.js">` include, a
`data:image/png;base64` URI, and the URL `http://localhost:3000` in issue text.

Held-out first run (`heldout_v1.json`):

| Metric | Value |
|--------|-------|
| Attacks | 17 |
| Benign | 4 |
| True positives | 11 |
| False negatives | 6 |
| False positives | 0 |
| Recall | 64.71% |
| False-positive rate | 0.00% |

Missed: numeric constant comparisons (`OR 2>1`), `OR 1--`, U+2215 path
separators, `127.1` loopback, IPv4-mapped IPv6 loopback, and `${env:...:-j}`
Log4Shell lookup assembly.

### Regression run after fixes

Both files currently report 100% recall and 0% false-positive rate in
`cargo test --test independent_corpus_test`. **These are in-sample regression
numbers.** Every case was used to drive the fixes above, so they say
"the pinned cases still pass", not "the engine catches X% of real attacks".

### Held-out measurement, `heldout_v2.json` (2026-11-04)

One run, produced before any engine change in response to these cases. Full
detail, including every miss and every blocked control, is in
`corpus/heldout_v2_report.json`.

| Metric | Value |
|--------|-------|
| Attacks | 98 |
| Benign controls | 57 |
| Detected | 55 |
| Missed | 43 |
| Controls cleared | 53 |
| Controls blocked | 4 |
| **Recall** | **56.1%** (95% CI 46.3%–65.5%) |
| **False-positive rate** | **7.0%** (95% CI 2.8%–16.7%) |

By family: XSS 12/12, GraphQL 4/4, prototype pollution 4/4, WordPress probes
5/6, path traversal 6/8, command injection 5/8, SQL injection 8/12, JWT 3/4,
framework exploit probes 3/8, sensitive-file probes 3/7, SSRF 1/8, XXE 1/2, and
**zero** detection for the five families the engine has no rules for at all:
NoSQL operator injection, SSTI, HTTP response splitting, Host-header injection
and malicious upload.

The four blocked controls are the honest cost of the signature set: an inline
SVG in a CSS value, a password containing `;ls -la`, the public
`/wp-json/wp/v2/posts` listing, and the WordPress `admin-ajax.php` heartbeat —
those two being the engine blocking ordinary use of the platform a customer
is most likely to run.

**What this number is:** the first out-of-sample estimate the project has
produced, on hand-written attacks and imagined traffic. **What it is not:** a
measurement against real customer logs, a certification, or a number to put on
the site without this paragraph next to it. The previous batches' 100%/0% are
still only in-sample regressions.

This batch is now spent. Any engine change made to close a miss listed in
`heldout_v2_report.json` turns `heldout_v2.json` into a third regression suite,
and the next honest estimate has to come from a new `heldout_v3` labelled
before it is run.

### Later held-out batches (`benchmarks/real_comparative/corpus/*.jsonl`)

Batches v3–v10 moved to JSONL corpora under
`benchmarks/real_comparative/corpus/` and were each measured once, then spent
as tuning inputs. Their one-shot figures remain in `STATUS.md` and the
generated reports for provenance:

| Batch | One-shot result | Status |
|-------|-----------------|--------|
| `heldout_v3`–`heldout_v7` | measured once each (see `STATUS.md`) | spent; regression floors |
| `heldout_v8` | 77.5% recall / 4.2% FPR | spent |
| `heldout_v9` | 50.0% recall / 6.4% FPR (`heldout_v9_report.json`) | spent; post-repair diagnostic 97.7%/4.3% |
| `heldout_v10` | one-shot **frozen result / 0.0% FPR** (`heldout_v10_report.json`, frozen); current engine **100%/0.0%** (`heldout_v10_post_tuning_report.json`) | the one-shot file is the publishable blind estimate; the 100%/0.0% file is the current-engine diagnostic on the same now-spent batch |

`crs_v430.jsonl` is the vendor-authored OWASP CRS v4.30 suite. Coverage against
it is an **in-sample** measurement (the engine was tuned on its misses),
currently 3,321/4,050 labelled attacks (82.0% recall). It is not an independent
or third-party evaluation.

## Rules for changing the corpus

1. Label a case before running it against the engine. Do not add a case and
   then label it from the engine output.
2. Keep the `note` and provenance. A case without a source is not reviewable.
3. When a case fails, fix the engine or document the gap. Do not delete the
   case to make the suite green.
4. If you consume a held-out batch by tuning against it, say so here and create
   a new batch instead of reusing the old label.
5. Do not publish corpus metrics as independent quality evidence. The
   `docs/` benchmark pages must link to this file and repeat the caveat.

## Running

```bash
cargo test --test independent_corpus_test -- --nocapture
```

The held-out batch is measured by its own test, which asserts nothing about
detection quality. Re-running it prints the same numbers; the committed report is
only rewritten when the variable is supplied, which is what keeps the first run
from being silently replaced by a later, tuned one:

```bash
HELDOUT_V2_REPORT=corpus/heldout_v2_report.json cargo test \
    --test heldout_v2_measurement_test -- --nocapture
```

The regression test prints per-category recall, every miss, every false positive, and
every category-attribution mismatch, then fails if any list is non-empty or
if recall/FPR cross the regression thresholds.
