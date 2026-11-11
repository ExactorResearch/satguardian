# 🛡️ SATGuardian — The WAF That Can Prove Its Work

> **Deterministic, auditable security decision layer.** Not another WAF — the
> engine that decides *why* a request is malicious, bit by bit, before any
> scoring-based firewall has to guess.

> **Status: SATGuardian Edge WAF v0.3.0.**
> Detection has been measured on project-authored corpora — see
> [STATUS.md](STATUS.md) for the evidence and its limits, including the
> honest statement that no third-party evaluation exists yet.

**📚 Official Documentation:** [https://exactorresearch.github.io/satguardian/](https://exactorresearch.github.io/satguardian/)

[![License](https://img.shields.io/badge/Edge_WAF-100%25_Free_&_Unlimited_Traffic-success.svg)](#-pricing)
[![Rust](https://img.shields.io/badge/Engine-Rust_u128_Bitmasks-orange.svg)](#-why-satguardian)

**SATGuardian Edge WAF** is a self-hosted **deterministic security decision
layer** written in Rust. It evaluates security logic with **128-bit integer
bitmasks (`u128`)** in ~0.5 ms in memory, and every block is a reproducible
Boolean proof — not an anomaly score. It can — only if you turn it on — send
recorded anomalies to **SATGuardian cloud synthesis** for review.

The product promise: **free, you get local protection; paying, you get ongoing
review, update proposals and explanations — without ever giving up control of
your WAF.** Cloud review is opt-in (`auto_sync_enabled` defaults to `false`)
and what it returns is stored as a **proposal**: nothing enters the running
rule set until you approve it.

## 🎯 Why SATGuardian

SATGuardian is not positioned as "another WAF". It is a **deterministic
decision layer** that does what signature- and scoring-based firewalls
structurally cannot:

1. **Every decision is auditable, bit by bit.** A block is a Boolean cube
   `(feature_vector & mask) == expected` over a 128-bit feature vector —
   reproducible and reviewable by an auditor without trusting a vendor's
   scoring internals. CRS-style engines answer "blocked, anomaly score 27";
   SATGuardian answers *which structural tokens, in which combination,
   triggered which rule*.
2. **It complements your existing WAF instead of replacing it.** Measured
   head-to-head against Aegis Community v1.1.0 (Coraza + OWASP CRS 4.25.1):
   on the CRS v4.30 attack suite the two engines detect **82.0% vs 80.7%**,
   and their coverage is strongly complementary — union **92.9% recall**,
   intersection only **69.8%**. In a cascade, SATGuardian adds detection the
   signatures miss; alone, it adds explainability they cannot offer.
3. **Your traffic never leaves your infrastructure.** No DNS redirection, no
   hosted gateway, no per-request fee. The only optional cloud contact is the
   review of recorded feature vectors — off by default, and its output arrives
   as proposals you approve, never as silent rule changes.
4. **Free edge, paid governance.** Edge inspection is 100% free and
   unlimited. The paid layer is *review*: ongoing analysis of new patterns,
   update proposals and explanations.

**Who this is for:** teams that need to *prove* why a request was blocked —
regulated workloads, audit-driven security programs, and operators who want a
fast deterministic first stage in front of a heavier WAF. **Who it is not for
(yet):** teams that need a managed console, TLS termination, geo-blocking or
rate limiting in the same box — those live in the proxy/TLS layer in front of
SATGuardian.

## 📊 Measured, not claimed

- **Detection parity on the vendor suite:** 82.0% vs Aegis+CRS 80.7% recall on
  the OWASP CRS v4.30 attack corpus (4,050 cases).
- **Complementary coverage:** 92.9% union recall — each engine catches what
  the other misses.
- **False positives:** 0.5% vs 22.9% on 665 pooled benign controls (project-
  authored corpus; partially in-sample — caveats in [STATUS.md](STATUS.md)).
- **Latency:** ~0.46 ms p50 / ~6 ms p99 in-memory, single thread, expanded
  rule set (re-measured 2026-11-10).

Full evidence, methodology, per-case verdicts and the replay harness:
[STATUS.md](STATUS.md) ·
[Comparative analysis](docs/benchmarks/comparative-analysis.md) ·
[Corpus provenance](corpus/README.md) ·
[Benchmark results](benchmarks/real_comparative/README.md)

## ⚡ Quick Start

Requires a Rust toolchain. Do **not** use the archived `dist/`/`releases/`
artefacts — they predate the claim corrections and the approval gate.

```bash
git clone https://github.com/ExactorResearch/satguardian.git
cd satguardian
cargo build --release

# Terminal 0: any upstream on :3000, e.g.  python -m http.server 3000
# Terminal A: WAF proxy on :8080
./target/release/satguardian-waf proxy --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000

# Benign -> proxied (200 if upstream serves it); attack -> 403 with proof
curl -i http://localhost:8080/
curl -i "http://localhost:8080/api/users?search=1%27%20UNION%20SELECT%20*%20FROM%20users--%20%3Cscript%3Ealert(1)%3C/script%3E"

# Built-in benchmark, 10,000 requests
./target/release/satguardian-waf benchmark -r 10000
```

## 🛰️ Shadow mode — evaluate on real traffic without blocking

For pilots and design partners: run SATGuardian in **monitor mode** and it
inspects every request, records detections and proofs in the local ledger —
but never blocks. Production traffic is never touched while you measure real
false-positive rates and latency:

```bash
./target/release/satguardian-waf proxy --mode monitor --listen 127.0.0.1:8080 --upstream http://127.0.0.1:3000
```

Same switch via `mode = "monitor"` in `waf_config.toml` or `WAF_MODE=monitor`.
Details: [Operations guide](docs/getting-started/operations.md).

## 🔌 Integrations: plugs into what you already run

SATGuardian is not another WAF competing with your stack — it is the
decision layer that plugs into what you already run:

- **Envoy · Istio · service mesh** — native `ext_authz` sidecar
  ([guide](ENVOY_INTEGRATION_GUIDE.md)).
- **nginx · HAProxy · Traefik · Caddy** — `auth_request` / `forward_auth`
  patterns mount it in front of your existing proxy, in minutes.
- **Kong · APISIX · Tyk** — gateway `ext-auth`/plugin integration.
- **Kubernetes Gateway API · OPA** — SATGuardian decides, OPA/Gatekeeper
  permits: "what was allowed" + "what was blocked and why".
- **Splunk · Sentinel · OpenTelemetry** — every block can reach your SIEM or
  tracing pipeline with its Boolean proof attached.

See the full [Integration Ecosystem](docs/integrations/index.md).

## 💰 Pricing

- **Edge WAF — free forever.** Local inspection is 100% free and unlimited;
  no per-request charge, no traffic tax.
- **Cloud Review — from $20/mo.** Ongoing analysis of new patterns, update
  proposals and explanations — you approve every change. Quota exhaustion
  pauses cloud review; local rules keep enforcing.
- **Enterprise — custom.** Higher volumes, more servers, negotiated terms.
  256+ variable matrices are engineering projects, not a plan.

*Internal metering (Security Units) and job ceilings are documented in the
technical guides — [configuration](docs/getting-started/configuration.md) ·
[operations](docs/getting-started/operations.md).*

## 📚 Documentation

- **Docs site:** https://exactorresearch.github.io/satguardian/
- **Engineering log & evidence:** [STATUS.md](STATUS.md)
- **White paper:** [satguardian_white_paper.md](satguardian_white_paper.md)
- **Architecture:** [ARCHITECTURE.md](ARCHITECTURE.md) ·
  [docs/architecture](docs/architecture/system-architecture.md)
- **Deployments:** [Envoy integration](ENVOY_INTEGRATION_GUIDE.md) ·
  [case study](CASE_STUDY_PRODUCTION_DEPLOYMENT.md)
- **Audit & reports:** [TECHNICAL_AUDIT_REPORT.md](TECHNICAL_AUDIT_REPORT.md) ·
  [docs/reports](docs/reports/technical-audit.md)

---

*© 2026 SATGuardian. Edge WAF released under Apache-2.0; detection
improvements come from the cloud service, which is not part of this binary.*
