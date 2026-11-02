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

Payload provenance is recorded per case in the `note` field and in the
`provenance` block: OWASP CRS/WSTG notes, PortSwigger filter-evasion notes,
Log4Shell obfuscation catalogues, RFC 7519 JWT fixtures, and benign snippets
modelled on framework/CDN documentation.

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
No held-out estimate exists after the second fix pass because the held-out set
was consumed.

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

The test prints per-category recall, every miss, every false positive, and
every category-attribution mismatch, then fails if any list is non-empty or
if recall/FPR cross the regression thresholds.
