# SATGuardian: Deterministic Layer-7 Web Application Firewall via Propositional Satisfiability

**Research & Engineering Team:** Satguardian Research
**Core Technologies:** Rust SAT Engine, Envoy Proxy (`ext_authz`), GXOR-Lattice Minimization
**Classification:** Systems Architecture & Academic Documento Técnico de Arquitectura

---

## Abstract

Layer-7 perimeter security in modern cloud-native environments presents a fundamental engineering trade-off: traditional regular expression (Regex) matching engines exhibit non-deterministic worst-case execution time ($O(2^n)$ backtracking) and elevated false-positive rates on structured data payloads (JSON, GraphQL). Conversely, modern off-cluster Machine Learning classifiers introduce unacceptable network latencies ($>300\text{ ms}$) and probabilistic non-determinism.

This paper introduces **SATGuardian**, a deterministic Layer-7 input validation system. By projecting canonicalized request tokens onto a finite Boolean variable space ($|\mathcal{V}| \le 128$) and evaluating security invariants as Conjunctive Normal Form (CNF) satisfiability checks, the engine eliminates algorithmic backtracking. It achieves strictly bounded sub-millisecond evaluation latency ($< 0.05\text{ ms}$) and mathematically verifiable causal proofs ($\LaTeX$) for every blocked request, ensuring absolute forensic explainability.

---

## 1. The Chomsky Hierarchy Mismatch & The ReDoS Threat

The fundamental vulnerability of traditional WAFs (e.g., ModSecurity, Cloudflare, AWS WAF) stems from a theoretical mismatch in formal language theory. 

Structured application payloads—including SQL queries, JSON documents, and GraphQL—belong to **Context-Free Languages** (Type-2 in the Chomsky Hierarchy). Regular expressions are strictly bound to **Regular Languages** (Type-3). Attempting to identify malicious context-free constructs using regular expressions forces rulesets to rely on brittle syntactic approximations.

### Algorithmic Complexity and ReDoS
Regex engines implementing Non-deterministic Finite Automata (NFA) with backtracking are susceptible to **Regular Expression Denial of Service (ReDoS)**. When an evaluated string fails to match after exploring ambiguous nested branches, the evaluator performs exhaustive backtracking across all permutation paths:
$$ \text{Time Complexity} = O(2^n) $$
Under pathological payload injection, a low-bandwidth attacker can lock a CPU core at $100\%$ utilization, triggering cascading gateway failures.

---

## 2. The Boolean Hypercube & Axiomatic Supervision

SATGuardian abandons pattern matching in favor of **Automated Theorem Proving** over finite propositional domains.

1. **Linear Tokenization ($O(n)$):** Incoming requests undergo single-pass lexical analysis. The engine normalizes encodings and extracts semantic tokens (e.g., `QUOTE`, `TAUTOLOGY_EQUALS`, `SCRIPT_TAG`).
2. **Boolean Projection:** Tokens are mapped onto a fixed-width bitvector $\mathbf{b} \in \{0, 1\}^{128}$, where each bit represents the presence ($1$) or absence ($0$) of a canonical proposition.
3. **Axiomatic Supervision:** Instead of relying on manual, error-prone human labeling, the system assigns a "malicious" label mathematically ($F(\mathbf{x}) = 1$) when a payload violates the rigid formal grammar of a protocol (e.g., JWT RFC 7519, GraphQL AST specs). 

---

## 3. Certainty Islands (Invariants)

Security policies are expressed as invariant clauses in Conjunctive Normal Form (CNF). The engine evaluates 10 formal **Certainty Islands**, covering both traditional and enterprise vectors:

* **ISLAND-SQLI:** Tautologies, UNION extraction, stacked DDL.
* **ISLAND-XSS:** Script contexts, event triggers, DOM pollution.
* **ISLAND-RCE & LFI:** Shell chains, subshells, path traversals.
* **ISLAND-GRAPHQL:** Introspection dumping, recursive cyclic nesting.
* **ISLAND-JSON-PROTO:** Prototype pollution (`__proto__`), nesting bombs.

A payload is safe if and only if the active token set $\mathcal{T}$ satisfies the conjunction of all security invariants $\mathcal{C}_{\text{WAF}}$. Because evaluations are executed via SIMD bitwise operations on CPU registers, the worst-case execution time is strictly constant ($O(1)$ after $O(n)$ lexing).

---

## 4. Autonomous Inductive Synthesis (SATGuardian Core)

Attackers continuously mutate payloads (e.g., injecting inline comments `/*...*/` or null bytes) to camouflage their vectors. In the Boolean hypercube, each variation represents a new minterm. Storing thousands of individual rules would saturate RAM and cache.

SATGuardian resolves this through **Autonomous Inductive Synthesis**:
1. Uncataloged anomaly minterms are securely transmitted to the `satguardian.tech` cloud engine.
2. The engine executes exact Boolean minimization using the **GXOR-Lattice algorithm**, which scales deterministically beyond the limits of classical Quine-McCluskey solvers.
3. The algorithm eliminates all camouflage variables (*Don't Cares*) and extracts the **Prime Implicant**.
4. The synthesized, irreducible Boolean rule is hot-compiled into the local WAF's RAM in microseconds. A single new rule immunizes the cluster against trillions ($2^{126}$) of future structural mutations.
5. In accordance with zero-trust data sovereignty, customer request traffic never transits SATGuardian servers; synthesis is billed purely in **Security Units (SU)** per Boolean optimization workload while local edge inspection remains 100% unlimited and free.

---

## 5. Mathematical Forensic Explainability

To meet strict compliance frameworks (e.g., PCI-DSS 4.0, SOC 2 Type II), edge security cannot rely on black-box probabilistic models. 

When SATGuardian blocks a request, it generates a formal resolution refutation proof. This proof is rendered directly into standard $\LaTeX$ notation and returned in the HTTP diagnostic headers or JSON payload:

$$
\begin{aligned}
\mathbf{Certainty\ Island} &: \{\mathcal{I}_{\text{SQLi}}\} \subset \mathcal{I}_{\text{SAT}} \\[4pt]
\mathbf{Active\ Tokens} &: \mathcal{T} = \{\texttt{QUOTE}, \texttt{TAUTOLOGY\_EQUALS}\} \\[4pt]
\mathbf{Invariant\ Rule} &: \mathcal{C}_{\text{WAF}} \equiv \neg (\texttt{SAT-SQLI-01}) \\[4pt]
\mathbf{SAT\ Evaluation} &: \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}) \equiv \mathbf{FALSE} \implies \mathbf{BLOCK}
\end{aligned}
$$

This provides unambiguous, auditable forensic evidence explaining exactly *why* a payload was intercepted, eliminating hallucination and guesswork for the SOC (Security Operations Center) team.

---
*Developed by Satguardian Research. Redefining edge security through deterministic mathematics.*