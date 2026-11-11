# 🔌 Integration Ecosystem

SATGuardian is not positioned as "another WAF" that competes with your stack — it is the **decision layer that plugs into what you already run**. Your infrastructure is already full of good pieces: Envoy in your mesh, Kong in your APIs, nginx at your edge, Istio in your Kubernetes, Splunk in your SOC. What none of them gives you is an answer to the question every auditor and every CISO eventually asks:

> *"Why was this request blocked?"*

SATGuardian answers that **bit by bit**, with a reproducible Boolean proof. And it integrates with the tools that already dominate the market:

---

## 🕸️ Envoy · Istio · Service Mesh — where microservice traffic lives

SATGuardian speaks `ext_authz` natively: it runs as a sidecar and every proxy in the mesh asks it before letting anything through. The decision travels with the request — there is no "score 27" to interpret, there is a Boolean function you can reproduce on your laptop.

**Why it matters:** if you already run Istio or Linkerd, SATGuardian gives them what they lack — an external authorization policy whose decision is **demonstrable**, not arguable.

**Status:** implemented and documented — see [Envoy Proxy Integration](../deployments/envoy-integration.md).

## ⚡ nginx · HAProxy · Traefik · Caddy — the proxy already in front

`auth_request` in nginx, `forward_auth` in Caddy/Traefik: SATGuardian mounts as an authorization service in minutes, without touching your routing or TLS configuration.

**Why it matters:** the cheapest entry point that exists. Download the binary, point your proxy at it, and you are already blocking with auditable proof — while your current WAF keeps working behind it.

## 🔀 Kong · APISIX · Tyk — the API gateway world

As a plugin or via `ext-auth`, SATGuardian inspects what API gateways validate by schema but cannot explain: *which exact combination of tokens* made a payload malicious.

**Why it matters:** gateways validate that a request *is well-formed*; SATGuardian decides whether it *should exist*. That is the layer nobody gives you today.

## ☸️ Kubernetes Gateway API · OPA — policy as code

SATGuardian produces the decision; OPA/Gatekeeper produces the policy. Together: "what was permitted" + "what was blocked and why" — complete traceability in zero-trust environments.

**Why it matters:** in regulated Kubernetes, "trust the mesh" is not an audit answer. "Here is the Boolean proof" is.

## 📡 Splunk · Sentinel · OpenTelemetry — your SIEM already exists, use it

Every block SATGuardian emits can reach your SIEM with its proof attached, or as a distributed-tracing span. The dashboard your security team already watches now shows *the reason* for the block, not just the event.

**Why it matters:** it turns security audit into data flowing through tools you already pay for — without learning anything new.

---

## What you get when you download it

- ✅ **Free, unlimited Edge WAF** — no per-request cost, forever
- ✅ **Detection measured against the real OWASP CRS** — technical parity, better false-positive handling
- ✅ **Auditable decisions** — every block is reproducible, not a hunch
- ✅ **Total sovereignty** — runs on your infrastructure; your data never leaves your network
- ✅ **The cloud only proposes** — new-threat analysis arrives as a rule *proposal* that **you approve**. It never applies itself

## The integration you will not see in any other WAF

SATGuardian does not ask you to choose it *instead of* your stack — it asks you to put it *in front*. Cloudflare, AWS WAF, Aegis, ModSecurity: all of them keep working. SATGuardian is the layer that decides **why**, and the proof your auditor can verify.

> **Download it. Point it at your favorite proxy. Watch your first block arrive with its proof attached.**

*SATGuardian — The WAF That Can Prove Its Work.*
