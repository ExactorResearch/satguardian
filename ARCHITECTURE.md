# Architectural Analysis: Exactor WAF Guardian

## 1. Introduction & Real Problem Solved
Traditional Web Application Firewalls (WAFs), primarily relying on regular expression engines (such as ModSecurity with OWASP CRS and its Go derivatives like Coraza), exhibit well-documented structural limitations: vulnerability to Regular Expression Denial of Service (ReDoS) via excessive backtracking, high false positive rates, and significant maintenance overhead.

Furthermore, they show weakness against modern obfuscation and complex payloads—especially GraphQL, deeply nested JSON, and polymorphic attack techniques.

This proposal defines **Exactor WAF Guardian** as a modern WAF designed from the ground up to overcome these challenges with a pragmatic, auditable, and production-ready approach. The system makes no promises of "100% mathematical certainty" or "perfect cold-start." Instead, it seeks a realistic balance between detection, latency, operability, and maintainability, explicitly accepting the inherent trade-offs of perimeter security.

---

## 2. Design Principles & Clean Architecture
The design focuses on delivering predictable latency and robust operability through a clean architecture:

- **Rust Core**: Built natively in Rust to guarantee memory safety, predictable performance, and zero garbage collection pauses.
- **Envoy Integration**: Native integration with Envoy via the `ext_authz` filter (or `ext_proc` for use cases requiring deep response body inspection or modification).
- **Sidecar Deployment**: Preferred deployment model as an isolated sidecar process. This allows a *fail-open* or *fail-closed* configuration based on organizational risk policy and avoids the strict memory and body size limits imposed by Proxy-WASM architectures. It also supports embedded library usage for services that prefer operating *in-process*.

### High-Level Architecture
```
Client → Envoy (or compatible proxy)
          │
          ▼ (ext_authz / local gRPC / UDS)
   WAF Sidecar (Rust)
   ├── Structured Parser
   ├── Logical Rules Evaluation + Scoring
   ├── Positive Security (where applicable)
   └── Decision (allow / log / block / challenge)
          │
          ▼
 Upstream / Service Mesh
```
The sidecar communicates via Unix Domain Sockets (UDS) or local gRPC to minimize network latency overhead.

---

## 3. Hybrid Detection Engine
To bypass regular expression inefficiencies, the engine uses a hybrid approach in the critical path:

1. **Strong Structured Parser**: Native parsing capabilities for HTTP, query strings, headers, JSON, GraphQL, and multipart data.
2. **Logical Rule Layer**: Use of simple, human-readable logical rules (boolean and comparison operators) rather than relying exclusively on complex regular expressions.
3. **Scoring & Thresholds**: Configurable scoring system that enables tiered reaction thresholds (log, challenge, or block) based on endpoint sensitivity.
4. **Positive Security**: Native support for endpoint or schema-based allow-lists where beneficial, significantly reducing operational noise.
5. **Controlled Hybrid Approach**: Ability to combine signature checks, semantic rules, and anomaly heuristics in a balanced manner without depending on opaque Machine Learning models in the critical path.

---

## 4. Offline Formal Verification (Not in the Hot Path)
The Exactor ecosystem leverages boolean algebra, normal forms (CNF/DNF), and satisfiability solvers (SAT/SMT). However, these formal techniques are strictly utilized in **offline background processes** and **never in the HTTP request critical path**.

Solvers are used within CI/CD pipelines and administrative workflows to:
- Transform and minimize rulesets.
- Detect logical overlaps and contradictions between security policies.
- Verify formal equivalence when adding or updating rule definitions.
- Generate compact, optimized rule matrix representations.

In the request *hot path*, only linear or strictly low-complexity, predictable evaluators are executed. Deliberately avoided in the hot path are SAT solvers, real-time graph isomorphism checks, or cellular automata calculations per request.

---

## 5. Observability & Operability
Operability for security and SRE teams is a foundational pillar:

- **Operating Modes**: Clear separation between *monitor mode* (log-only) and *enforce mode* (active blocking).
- **Fine-Grained Exclusions**: Granular exclusion rules by rule ID, parameter, route, or IP to fine-tune the system.
- **Exportable Metrics**: Comprehensive metric exposure (p50, p95, and p99 latency percentiles, block rates, estimated false positives) sent to corporate monitoring tools like Prometheus.
- **Traceability**: Structured logs providing clear decision explanations for every request action.
- **Management**: Simple dashboard and dedicated API for managing rules and exceptions.

---

## 6. Empirical Approach & Honest Limitations
The architecture promotes continuous evaluation against public and private datasets of real-world attacks and benign traffic. The WAF encourages transparent benchmarking against market alternatives such as Coraza, SafeLine, and ModSecurity, focusing on empirical latency measurements under load and real-world false positive rates.

Like any security control, it has genuine limitations:
- No promises of "zero false positives" or "perfect detection without prior data."
- Requires human tuning.
- Latency remains subject to local loopback communication overhead (gRPC/Unix Sockets).
- Successful adoption demands operational maturity in cloud-native environments.

---

## 7. Value Summary
This architecture prioritizes:
- Predictable performance and low latency.
- Real auditability of security rules.
- Clear operability for security and SRE teams.
- Controlled ruleset evolution using formal tools strictly offline.
- Native integration with modern cloud-native ecosystems (Envoy, Kubernetes, Service Mesh).

*This is not a theoretical revolution. It is a practical, disciplined evolution of established principles, eliminating the most painful structural and operational weaknesses of legacy regex-based WAFs.*
