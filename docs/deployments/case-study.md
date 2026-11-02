# Deployment Notes & Forensic Ledger Walkthrough (Lab Environment)

**Environment:** local/staging deployment of `satguardian` v0.3.0  
**Data sources:** bundled demonstration SQLite ledger (`waf_ledger.db`), the native
Rust benchmark, and the Python stand-in harness

> **Status: research prototype.** This is not a customer production deployment
> and does not demonstrate production readiness. Numbers below come from the
> bundled ledger and the in-repo corpus. See [STATUS.md](../status.md) and
> [corpus/README.md](../corpus.md).

---

## 1. Summary

1. **Forensic ledger walkthrough:** the bundled `waf_ledger.db` contains recorded
   demo traffic that can be re-analysed with `satguardian-advisor.py`. Row counts
   depend on the ledger revision; regenerate the audit before quoting them.
2. **Native Rust hot path:** `satguardian-waf benchmark -r 10000` evaluates the
   pinned corpus in memory, single-threaded. On a desktop CPU this lands in the
   tens of microseconds per payload; it excludes TLS, the proxy hop and the
   upstream service.
3. **Python harness:** `python run_benchmark.py 1000` compares the Python
   reference port against local Python stand-ins. It does not execute Coraza,
   SafeLine, ModSecurity or an LLM.

> **Correction notice:** earlier versions of this document capped accuracy at
> `99.9%`, floored error rates at `< 0.1%`, and presented Python stand-ins as
> vendor products. Those numbers and labels were removed.

---

## 2. Forensic Ledger Walkthrough (`waf_ledger.db`)

Generated with `python satguardian-advisor.py --report audit_report.html` and
`python satguardian-advisor.py --report-md audit_report.md`.

### 2.1 Traffic Taxonomy (bundled demonstration ledger)

| Traffic category | Recorded volume | Enforcement action | Notes |
| :--- | :---: | :--- | :--- |
| Benign application traffic | `1,663` | `ALLOW` | Used for collision replay |
| SQL injection | `951` | `BLOCK` | Multiple `SAT-SQLI-*` invariants |
| Cross-site scripting | `477` | `BLOCK` | Multiple `SAT-XSS-*` invariants |
| Path traversal | `472` | `BLOCK` | `SAT-PATH-*` invariants |
| Rate-limited bursts | `234` | `BLOCK` | Token-bucket state rule |
| SSRF | `2` | `BLOCK` | Metadata/loopback targets |
| **Total** | **`3,799`** | **`2,136` blocked / `1,663` allowed** | Demo data, not a customer tenant |

The ledger is demo data. It is useful for exercising the advisor pipeline; it is
not evidence that the engine is correct on real traffic.

### 2.2 Offline Rule Synthesis and Replay

The advisor analyses the ledger and proposes rule candidates, then replays each
candidate against the benign records to find collisions.

| Candidate | Basis | Replay gate | Operational effect |
| :--- | :--- | :---: | :--- |
| `biz-ban-ip-169-254-54-10` | Source IP concentrated attack events | see advisor report | Drops the hostile IP in fast path |
| `biz-method-api-users` | Benign traffic on `/api/users` used `GET` only | see advisor report | Restricts unused methods |
| `biz-method-api-v1-search` | Benign traffic used `GET` only | see advisor report | Restricts route surface |
| `biz-method-api-v1-users-profile` | Benign traffic used `GET` only | see advisor report | Restricts route surface |
| `biz-method-api-waf-metrics` | Benign traffic used `GET` only | see advisor report | Restricts telemetry endpoint |
| `cloud_sync_pending_anomalies` | Novel minterms awaiting synthesis | n/a (cloud step) | Compresses minterms via EXACTOR GXOR |

Replay outcomes depend on the ledger contents and rule thresholds. The advisor
prints the collision count for each candidate; no fixed floor is claimed here.

---

## 3. Measurements and Limits

| Measurement | Source | Result |
| :--- | :--- | :--- |
| Detection, pinned corpus | `corpus/independent_v1.json` (63 attacks, 16 benign) | 63/63 attacks, 0/16 benign blocked (in-sample regression) |
| Detection, first run before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Detection, second batch first run | `corpus/heldout_v1.json` (17 attacks, 4 benign) | 11/17 recall (64.71%), 0/4 benign blocked |
| In-memory latency, native Rust | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load |
| Python harness | `run_benchmark.py 1000` | Printed with provenance; local stand-ins only |

### Operational conclusions

1. **Latency is in-memory only.** The Rust engine evaluates rules in tens of
   microseconds per payload. No end-to-end proxy latency has been characterized.
2. **Evasion coverage is a regression floor.** The current corpus passes after
   being used to drive fixes. It does not establish coverage of unseen payloads.
3. **No production guarantees.** There is no third-party evaluation, soak test,
   or real-product comparison. Treat this document as a lab walkthrough.
