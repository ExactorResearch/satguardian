# Lab Walkthrough & Forensic Ledger Notes (Not a Customer Deployment)

> **Read this before quoting anything below.** This document is a walkthrough of
> a research prototype run on our own machine, against the SQLite ledger that is
> committed to the repository as demo data. It is **not** a customer deployment,
> not a production environment, and not production evidence of any kind. No
> third-party traffic, no third-party evaluation and no long-running soak is
> involved. The file keeps its original name so the documentation navigation
> still resolves. See [STATUS.md](../status.md) and [corpus/README.md](../corpus.md).

**Environment:** local/staging lab run of `satguardian` v0.3.0 on the project's own development machine  
**Data sources:** bundled demonstration SQLite ledger (`waf_ledger.db`), the native
Rust benchmark, and the Python stand-in harness

> **Status: research prototype.** This is not a customer production deployment
> and does not demonstrate production readiness. Every number below comes from
> the bundled demo ledger or the in-repo corpus, on one machine.

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
4. **Nothing in this walkthrough changed a rule set automatically.** Cloud review
   is off by default (`auto_sync_enabled = false`), and when it runs it leaves
   proposals in the ledger for a human to approve. The protection you see here is
   the built-in rule matrix that ships in the binary.

> **Correction notice:** earlier versions of this document capped accuracy at
> `99.9%`, floored error rates at `< 0.1%`, and presented Python stand-ins as
> vendor products. Those numbers and labels were removed. The held-out figures in
> §3 replace them.

---

## 2. Forensic Ledger Walkthrough (`waf_ledger.db`)

Generated with `python satguardian-advisor.py --report audit_report.html` and
`python satguardian-advisor.py --report-md audit_report.md`. **The input is the
demo ledger committed to this repository, so the output is a pipeline exercise,
not evidence about real traffic.**

### 2.1 Traffic Taxonomy (bundled demonstration ledger)

| Traffic category | Recorded volume | Enforcement action | Notes |
| :--- | :---: | :--- | :--- |
| Benign application traffic | `1,663` | `ALLOW` | Used for collision replay |
| SQL injection | `951` | `BLOCK` | Multiple `SAT-SQLI-*` invariants |
| Cross-site scripting | `477` | `BLOCK` | Multiple `SAT-XSS-*` invariants |
| Path traversal | `472` | `BLOCK` | `SAT-PATH-*` invariants |
| Rate-limited bursts | `234` | `BLOCK` | Sliding-window state rule (`SAT-STATE-01`) |
| SSRF | `2` | `BLOCK` | Metadata/loopback targets |
| **Total** | **`3,799`** | **`2,136` blocked / `1,663` allowed** | Demo data, not a customer tenant |

The ledger is demo data. It is useful for exercising the advisor pipeline; it is
not evidence that the engine is correct on real traffic.

### 2.2 Rule Proposals and Replay

The advisor analyses the ledger and proposes rule candidates, then replays each
candidate against the benign records to find collisions. **A candidate is a
proposal: it changes nothing until the operator approves it** (`--dry-run` lists
them without applying).

| Candidate | Basis | Replay result (this demo ledger) | Effect if approved |
| :--- | :--- | :--- | :--- |
| `biz-ban-ip-169-254-54-10` | Source IP concentrated attack events | `154 collisions` against allowed rows — the operator sees this before deciding | Drops the hostile IP in fast path |
| `biz-method-api-users` | Benign traffic on `/api/users` used `GET` only | No collisions / 1663 allowed | Restricts unused methods |
| `biz-method-api-v1-search` | Benign traffic used `GET` only | No collisions / 1663 allowed | Restricts route surface |
| `biz-method-api-v1-users-profile` | Benign traffic used `GET` only | No collisions / 1663 allowed | Restricts route surface |
| `biz-method-api-waf-metrics` | Benign traffic used `GET` only | No collisions / 1663 allowed | Restricts telemetry endpoint |
| `cloud_sync_pending_anomalies` | `14` novel minterms recorded as patterns awaiting analysis | Not replayed locally; the cloud step returns compiled clauses | Sent to SATGuardian cloud synthesis **only if the operator opts in**; results arrive as proposals (`dynamic_clauses.applied = 0`) and enforce only after `satguardian-waf clauses apply <id>` |

Replay outcomes depend on the ledger contents and rule thresholds. The advisor
prints the collision count for each candidate; no fixed floor is claimed here,
and "no collisions" on demo traffic is not a false-positive guarantee.

---

## 3. Measurements and Limits

| Measurement | Source | Result |
| :--- | :--- | :--- |
| Detection, pinned corpus | `corpus/independent_v1.json` (63 attacks, 16 benign) | 63/63 attacks, 0/16 benign blocked (**in-sample regression floor**) |
| Detection, first run before fixes | same corpus | 51/63 recall (80.95%), 3/16 benign blocked (18.75% FPR) |
| Detection, second batch first run | `corpus/heldout_v1.json` (17 attacks, 4 benign) | 11/17 recall (64.71%), 0/4 benign blocked; batch since consumed |
| **Held-out detection (current engine)** | `benchmarks/real_comparative/corpus/heldout_v10.jsonl` (70 attacks, 44 controls) | current engine **100% recall / 0.0% FPR** (post-tuning diagnostic, `heldout_v10_post_tuning_report.json`); frozen one-shot **38.6% recall / 0.0% FPR** (`heldout_v10_report.json`) |
| Held-out detection (earlier, provenance) | `corpus/heldout_v2.json` (98 attacks, 57 controls), one run on 2026-11-04 | **56.1% recall** (95% CI 46.3–65.5%), **7.0% false-positive rate** (95% CI 2.8–16.7%) |
| In-memory latency, native Rust | `benchmark -r 10000` | p50 `~20 µs`, mean `~22 µs`, p99 near `50 µs` depending on load; in-memory only |
| Python harness | `run_benchmark.py 1000` | Printed with provenance; local stand-ins only |

### Operational conclusions

1. **Latency is in-memory only.** The Rust engine evaluates rules in tens of
   microseconds per payload on this machine. No end-to-end proxy latency has been
   characterized.
2. **The 100%/0% corpus rows are regression floors.** They pass because those
   cases were used to drive fixes. The honest out-of-sample measurement is the
   `heldout_v10` rows: **100% recall / 0.0% FPR** for the current engine (post-
   tuning diagnostic) and **38.6% / 0.0%** for the frozen one-shot estimate, on payloads
   written inside this project (the earlier `heldout_v2` row, 56.1%/7.0%, remains
   for provenance)
   written inside this project.
3. **No production guarantees.** There is no third-party evaluation, no soak
   test, no customer access log and no real-product comparison. Treat this
   document as a lab walkthrough of a research prototype.
4. **What the lab run does show** is the operating model: the node protects
   itself locally and offline by default, review of new patterns is opt-in, and
   every change to the enforcing rule set is an explicit operator approval.
