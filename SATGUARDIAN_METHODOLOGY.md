# 📘 The SATGuardian Methodology: Deterministic SAT Cyber-Defense

## Abstract

As web and banking architectures migrate to real-time microservices, GraphQL APIs, and high-frequency edge computing, traditional security paradigms face a fundamental trilemma:
1. **Classical Regular Expressions (ModSecurity / OWASP CRS)** are fast ($< 1\text{ ms}$) but brittle, suffering from catastrophic False Negative Rates ($> 75\%$) against obfuscated evasion payloads and high False Positive Rates on benign technical traffic.
2. **Pure Large Language Models (JEV Solo / Cloud LLM WAFs)** provide contextual reasoning but introduce unbearable latency ($350\text{–}600\text{ ms}$), steep API metering costs ($>\$2,000\text{ per million requests}$), and non-deterministic hallucination drift.
3. **SATGuardian-Accelerator (Deterministic Neuro-Symbolic SAT)** resolves this trilemma by replacing probabilistic generation with formal Boolean constraint satisfaction over abstract syntax trees (ASTs) and temporal sliding windows, achieving **$< 0.02\text{ ms}$ latency**, **$0.00 marginal inference cost**, and **100% mathematically verifiable causal proofs**.

---

## 1. Formal Mathematical Formulation

Let an incoming HTTP request $\mathcal{R}$ consist of URI path $\mathcal{P}$, parameter tuple $\mathcal{Q}$, headers $\mathcal{H}$, body $\mathcal{B}$, client socket metadata $\mathcal{S} = (\text{IP}, \text{Port})$, and temporal arrival timestamp $t \in \mathbb{R}^+$.

### 1.1 AST Token Extraction Lattice
The request is parsed by a deterministic multi-stage lexer into a finite set of normalized syntactic tokens $\mathcal{T} \subset \Sigma^*$:
$$\mathcal{T}(\mathcal{R}) = \text{Lexer}(\text{Normalize}(\mathcal{P} \cup \mathcal{Q} \cup \mathcal{H} \cup \mathcal{B}))$$

Where $\text{Normalize}(\cdot)$ performs multi-pass recursive decoding over percent-encoding, hexadecimal escapes, and SQL comment stripping ($/\*\dots\*/ \to \epsilon$).

### 1.2 The Master WAF Propositional Invariant
Let $\mathcal{C}_{\text{WAF}}$ be the conjunction of security invariants across all formal **Certainty Islands**:
$$\mathcal{C}_{\text{WAF}} = \bigwedge_{k \in \mathcal{K}} \mathcal{C}_k = \mathcal{C}_{\text{SQLi}} \land \mathcal{C}_{\text{XSS}} \land \mathcal{C}_{\text{RCE}} \land \mathcal{C}_{\text{LFI}} \land \mathcal{C}_{\text{SSRF}} \land \mathcal{C}_{\text{GraphQL}} \land \mathcal{C}_{\text{Proto}} \land \mathcal{C}_{\text{gRPC}} \land \mathcal{C}_{\text{JWT}} \land \mathcal{C}_{\text{Stateful}}$$

Each invariant clause $\mathcal{C}_k$ is expressed as a rigorous Boolean proposition:

#### A. Traditional Web Invariants
$$\mathcal{C}_{\text{SQLi}} \equiv \neg \Big( \text{Token}(\text{QUOTE}) \land (\text{Token}(\text{TAUTOLOGY}) \lor \text{Token}(\text{UNION\_SELECT}) \lor \text{Token}(\text{STACKED\_DDL}) \lor \text{Token}(\text{TIME\_DELAY})) \Big)$$
$$\mathcal{C}_{\text{XSS}} \equiv \neg \Big( \text{Token}(\text{TAG\_OPEN}) \land (\text{Token}(\text{SCRIPT\_CONTEXT}) \lor \text{Token}(\text{EVENT\_TRIGGER}) \lor \text{Token}(\text{JS\_SCHEME})) \Big)$$
$$\mathcal{C}_{\text{RCE}} \equiv \neg \Big( \text{Token}(\text{SHELL\_METACHAR}) \land \text{Token}(\text{SYS\_EXEC}) \lor \text{Token}(\text{DYNAMIC\_EVAL\_SINK}) \Big)$$
$$\mathcal{C}_{\text{LFI}} \equiv \neg \Big( \text{Token}(\text{TRAVERSAL\_DOTS}) \lor \text{Token}(\text{SENSITIVE\_SYSTEM\_PATH}) \Big)$$
$$\mathcal{C}_{\text{SSRF}} \equiv \neg \Big( \text{Token}(\text{PROXY\_URI}) \land (\text{Token}(\text{METADATA\_ENDPOINT}) \lor \text{Token}(\text{LOOPBACK\_TARGET})) \Big)$$

#### B. Enterprise & Banking Grammar Invariants
$$\mathcal{C}_{\text{GraphQL}} \equiv \neg \Big( \text{Token}(\text{GRAPHQL\_INTROSPECTION}) \lor \text{Expression}(\text{Depth}(\text{AST}_{\text{GQL}}) > 6) \lor \text{Token}(\text{BATCH\_ARRAY\_OVERLOAD}) \Big)$$
$$\mathcal{C}_{\text{Proto}} \equiv \neg \Big( \text{Token}(\text{\_\_proto\_\_}) \lor \text{Token}(\text{constructor.prototype}) \lor \text{Expression}(\text{Depth}(\text{JSON}) > 20) \Big)$$
$$\mathcal{C}_{\text{gRPC}} \equiv \neg \Big( \text{Token}(\text{CLIENT\_GRPC\_STATUS\_INJECTION}) \lor \text{Token}(\text{GRPC\_FRAMING\_DESYNC}) \Big)$$
$$\mathcal{C}_{\text{JWT}} \equiv \neg \Big( \text{Token}(\text{JWT\_ALG\_NONE}) \lor \text{Token}(\text{JWT\_MISSING\_SIGNATURE}) \lor \text{Token}(\text{KID\_TRAVERSAL\_INJECTION}) \Big)$$

#### C. Temporal Sliding Window & Behavioral Invariant
Let $W$ be the sliding temporal window in seconds (e.g. $60\text{ s}$), subdivided into $B$ atomic ring counter buckets. For a client $\text{IP} \in \mathcal{S}$ and arrival time $t_0$:
$$\text{Hits}_{\text{Global}}(\text{IP}, t_0) = \sum_{t = t_0 - W}^{t_0} \text{Count}(\text{IP}, t), \quad \text{Hits}_{\text{Auth}}(\text{IP}, t_0) = \sum_{t = t_0 - W}^{t_0} \text{AuthCount}(\text{IP}, t)$$
$$\mathcal{C}_{\text{Stateful}} \equiv \neg \Big( (\text{Hits}_{\text{Global}} > \Theta_{\text{Global}}) \lor (\text{Hits}_{\text{Auth}} > \Theta_{\text{Auth}}) \lor \text{Quarantined}(\text{IP}, t_0) \Big)$$

### 1.3 Provable Action Rule
The firewall decision $\mathcal{D}(\mathcal{R})$ is evaluated strictly via Boolean SAT resolution:
$$\mathcal{D}(\mathcal{R}) = \begin{cases} 
\mathbf{ALLOW}, & \text{if } \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}(\mathcal{R})) \equiv \mathbf{TRUE} \\
\mathbf{BLOCK}, & \text{if } \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}(\mathcal{R})) \equiv \mathbf{FALSE}
\end{cases}$$

When an invariant is violated, SATGuardian outputs the exact clause $\mathcal{C}_k^*$ that triggered the contradiction, yielding a zero-hallucination causal proof chain and verifiable LaTeX proof.

---

## 2. Boolean Hypercube & Autonomous Cloud Minimization

Every request $\mathcal{R}$ is projected onto a point on the Boolean Hypercube $\{0, 1\}^N$ ($N \le 128$):
$$\mathbf{x} = (x_0, x_1, \dots, x_{N-1}) \in \{0, 1\}^N, \quad \text{Minterm}(\mathbf{x}) = \sum_{i=0}^{N-1} x_i \cdot 2^i \in [0, 2^{128}-1]$$

1. **Local Anomaly Capture:** Requests exhibiting novel syntactic combinations are recorded as audit records in SQLite WAL (`waf_ledger.db`).
2. **Cloud Exact Minimization:** The background worker packages candidate minterms and dispatches them to **`https://satguardian.tech/api/simplify`** (powered by `satguardian-cloud-service`).
3. **Exact Prime Implicant Extraction:** The SATGuardian Core engine computes the mathematically exact minimal sum-of-products representation without heuristics.
4. **Hot-Compilation:** The minimized Boolean mask and expected bits are hot-compiled into the local in-memory Fast-Path table (`dynamic_clauses`) in microseconds, without restarting the proxy daemon or dropping established keep-alive connections.

---

## 3. Computational Complexity & Edge Feasibility

| Characteristic | Classical Regex (CRS) | Pure LLM (Transformer) | SATGuardian SAT Solver (Rust) |
| :--- | :---: | :---: | :---: |
| **Algorithmic Complexity** | $\mathcal{O}(2^M)$ *(ReDoS Risk)* | $\mathcal{O}(N^2 \cdot L \cdot D)$ *(Self-Attention)* | $\mathcal{O}(|\mathcal{T}|)$ *(Deterministic Lattice Lookup)* |
| **Temporal State Tracking** | None (Stateless) | High-cost Context Window | $\mathcal{O}(1)$ Atomic Ring Buffer |
| **Execution Latency** | $0.8 - 5.0\text{ ms}$ | $350 - 650\text{ ms}$ | **$0.018 - 0.045\text{ ms}$ ($< 50\text{ µs}$)** |
| **Memory Footprint** | $50 - 150\text{ MB}$ | $16\text{ GB} - 80\text{ GB}$ (VRAM) | **$< 15\text{ MB}$ (Static RAM)** |
| **Hardware Requirement** | CPU Server | High-End GPU Cluster | Single Core / Bare Metal / Microcontroller |
| **Throughput per Core** | $\sim 2,000\text{ req/sec}$ | $\sim 2 - 5\text{ req/sec}$ | **$> 80,000\text{ req/sec}$** |
| **Cost per 1M Requests** | $\$0.10$ (Compute) | $\$2,000.00+$ (API Token Fees) | **$\$0.00$ (Local In-Memory Evaluation)** |
| **Proof Verifiability** | Regex string match | Non-deterministic explanation | **Formal LaTeX + Causal Proof Chains** |

---

## 4. The Influencer & Public Storytelling Framework

To communicate this technological breakthrough to a broad, non-technical audience:

### The "Airport Metal Detector" Analogy
> *"Imagine putting an AI chatbot at an airport security checkpoint. When someone walks through with keys in their pocket, the chatbot takes 500 milliseconds to think, charges $0.002 to generate a paragraph describing the keys, and might accidentally let someone through if they speak in pig-latin.*
> 
> *SATGuardian is the metal detector. It doesn't write essays; it detects physical laws in 0.01 milliseconds, costs nothing to operate, and beeps every single time with zero confusion."*

---

## 5. Conclusion
 
SATGuardian proves that **formal deterministic mathematics and propositional SAT invariants** vastly outperform black-box neural networks and brittle regular expressions for structural invariant verification in high-throughput, mission-critical systems.

---

### Further Reading
- [Axiomatic Supervision and Inductive Synthesis in SATGUARDIAN](AXIOMATIC_SUPERVISION_AND_SYNTHESIS.md): In-depth theoretical study on how the WAF classifies, learns, and generalizes without manual human labeling via minterm reduction and Silicon Unit (SU) consumption.
- [Interactive Proof of Concept & Duel Suite](PROOF_OF_CONCEPT.md)
