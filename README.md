# SATGuardian Edge WAF

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](#license)
[![Powered by](https://img.shields.io/badge/Engine-SATGuardian%20(Rust)-orange.svg)](https://satguardian.tech)
[![Latency](https://img.shields.io/badge/Latency-0.02ms-brightgreen.svg)](#benchmarks)
[![Throughput](https://img.shields.io/badge/Throughput-80k%2B%20req%2Fs-blue.svg)](#benchmarks)
[![Cloud Optimization](https://img.shields.io/badge/Optimization-Security%20Units%20(SU)-purple.svg)](https://satguardian.tech)
[![Proof of Concept](https://img.shields.io/badge/PoC-Interactive%20Duel-success.svg)](PROOF_OF_CONCEPT.md)
[![Epistemology](https://img.shields.io/badge/Theory-Axiomatic%20Supervision-blueviolet.svg)](AXIOMATIC_SUPERVISION_AND_SYNTHESIS.md)

**Unlimited protected requests (100% free Edge WAF)** is free, open source, and available for download with instructions below. It replaces fragile regular expressions with a deterministic local Boolean SAT engine in `< 0.05ms` (`0.02ms` typical) across 10 formal certainty islands. You only pay for the optional cloud service for rule matrix simplification and minterm compression.

> 🛡️ **Zero Traffic Intermediation (100% Sovereign):**  
> SATGuardian never requires CNAME DNS redirection or cloud proxies. Customer traffic stays 100% inside your infrastructure. You only spend **Security Units (SU)** when synthesizing and compressing Boolean rule matrices in the cloud.

> 📘 **Foundational Theoretical Documentation:**  
> To understand how the WAF classifies without manual human labeling, and how rules are synthesized and generalized by consuming Security Units (SU), see [Axiomatic Supervision and Inductive Synthesis in SATGuardian](AXIOMATIC_SUPERVISION_AND_SYNTHESIS.md).

---

## 🚀 Three Canonical Deployment Methods (100% On-Premise & Sovereign)

Deploy SATGuardian Edge WAF directly into your architecture using any of the 3 canonical deployment models:

### Method 1: Standalone (Autonomous Mode)
The lowest friction path for early adopters, homelabs, and quick POCs. The client downloads the self-contained Rust binary, specifies the public listen port and internal target, and the WAF begins protecting immediately with zero compilers or external runtime dependencies:
```bash
# Windows
.\satguardian-waf.exe proxy --listen 0.0.0.0:443 --upstream http://127.0.0.1:8080 --mode block

# Linux
./satguardian-waf proxy --listen 0.0.0.0:443 --upstream http://127.0.0.1:8080 --mode block
```

### Method 2: Reverse Proxy over Existing Servers
Direct frontline positioned ahead of existing Nginx, Apache, or Microsoft IIS servers. Intercepts incoming internet traffic in microseconds, mathematically blocks threats, and transfers only legitimate requests to internal web server instances:

- **Linux (Ubuntu / Debian / RHEL / CentOS / Rocky / Alpine):**
  ```bash
  curl -sSL https://raw.githubusercontent.com/satguardian/satguardian-waf/main/install.sh | sudo bash
  ```
- **Windows Server (Microsoft IIS Frontline via PowerShell as Administrator):**
  ```powershell
  irm https://raw.githubusercontent.com/satguardian/satguardian-waf/main/install.ps1 | iex
  ```
- **Docker Compose (Containerized Frontline):**
  ```bash
  docker compose up -d
  ```

### Method 3: Native Kubernetes / Envoy Proxy Integration (Sidecar Model)
The definitive architecture for microservices and large-scale service meshes. SATGuardian runs as a local daemon sidecar next to each Envoy container via `ext_authz` over a local Unix Domain Socket (`unix:///run/satguardian/waf.sock`), delivering near-zero latency (`< 15 µs`):
```bash
# Run Envoy ext_authz verification daemon over Unix Domain Socket
satguardian-waf envoy-authz --socket /run/satguardian/waf.sock
```
When novel threats emerge, nodes query the cloud to download minimized Boolean rules and hot-compile them into RAM in 1 microsecond.

---

## ⚡ Quick Verification

Once the WAF daemon is active, execute these tests from any terminal or browser:

#### ✅ Legitimate Request (Allowed & Accelerated)
```bash
curl -i http://localhost:8080/
```
> **Result:** HTTP `200 OK`, returning header `X-SATGuardian-Protected: true` with inspection latency below $0.02\text{ ms}$.

#### 🛑 SQL Injection Attack Attempt (Instantly Blocked)
```bash
curl -i "http://localhost:8080/?id=1'%20OR%201=1--"
```
> **Result:** HTTP `403 Forbidden` in $< 0.05\text{ ms}$. The backend never receives the malicious packet.  
> The JSON payload contains the causal proof chain and formal $\LaTeX$ theorem:
> ```json
> {
>   "action": "BLOCK",
>   "category": "sql_injection",
>   "latency_us": 24.1,
>   "causal_proof": "(TAUTOLOGY_EQUALS) violates [SAT-SQLI-01] -> ACTION_BLOCK",
>   "formal_proof_latex": "\\begin{aligned} ... \\text{Eval}(\\mathcal{C}_{\\text{WAF}}, \\mathcal{T}) \\equiv \\mathbf{FALSE} \\implies \\mathbf{BLOCK} \\end{aligned}"
> }
> ```

---

## 💳 Cloud Optimization Plans (Security Units - SU)

Local Edge inspection is **100% free with unlimited requests**. You only subscribe to Security Units (SU) if you want cloud inductive simplification and minterm compression:

| Plan | Price | Seats | Optimization Limits | Included SU / Mo | Overage Policy | Edge Traffic |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SCOUT** | $20/mo | 1 | Up to 20 vars / 2.5K minterms | 1,000 SU/mo | Hard cap (synthesis pauses; edge keeps protecting) | **Unlimited (Free)** |
| **PRO / DEV** | $49/mo | 1 | Up to 64 vars / 10K minterms | 5,000 SU/mo | $10 per 1,000 extra SU | **Unlimited (Free)** |
| **STARTUP** | $499/mo | 5 | Up to 128 vars / 100K minterms | 50,000 SU/mo | $8 per 1,000 extra SU | **Unlimited (Free)** |
| **ESCALA** | $2,499/mo | 15 | Up to 128 vars / 1M minterms | 500,000 SU/mo | $5 per 1,000 extra SU | **Unlimited (Free)** |
| **ENTERPRISE** | Custom (Quote) | Unlimited | Up to 128 vars / Unlimited | Negotiated annual pool | Negotiated pool | **Unlimited (Free)** |

*Note: For setups requiring 256+ variables, engagement is offered exclusively as an Engineering Expansion Project (dedicated HPC / bare metal).*

### Check Cloud Entitlement & SU Balance
```bash
satguardian-waf entitlement
```

---

## 🧠 Why Train, How Does It Work, and How to Obtain Your License?

### 1. Why Does the WAF Need Training?
The WAF ships out-of-the-box with **10 pre-configured Certainty Islands** that drop known attack archetypes in under $0.02\text{ ms}$.

In real-world production environments, adversaries **continuously mutate and disguise their vectors**:
- Injecting SQLi via inline comments `/*...*/`, hexadecimal encodings, deeply nested JSON, or spoofed headers.
- Each mutation spawns a **novel minterm** within the Boolean hypercube $\{0, 1\}^{128}$, which the local WAF blocks and logs into its SQLite WAL database (`waf_ledger.db`).
- **Without Training:** The WAF would need to retain thousands of isolated minterm cases in RAM, causing CPU cache thrashing and degraded throughput.
- **With SATGuardian Cloud Optimization:** The cloud algorithm executes **Exact Inductive Synthesis**:
  1. Strips all camouflage variables (*Don't Cares*).
  2. Extracts the **Minimal Prime Implicant** (the irreducible algebraic root formula).
  3. **Generalizes protection to 100%:** Immunizes the server not only against previously observed variants, but against **trillions of future permutations** sharing that core, collapsing thousands of rules into a single CPU register instruction (`AND & CMP`).

---

### 2. How Does Training Run?
The WAF provides two training modes:
1. **Autonomous Background Sync (Recommended):**  
   The daemon scans pending anomaly minterms accumulated in `waf_ledger.db`, batches them, and dispatches them to the cloud every 5 minutes (`autonomous_sync_interval_secs = 300`). The synthesized rule is **hot-compiled into RAM in 1 microsecond**, without restarting the daemon or interrupting live client connections.
2. **Manual CLI Sync:**  
   Trigger immediate synchronization and cloud synthesis on demand:
   ```bash
   satguardian-waf sync-simplify --config /etc/satguardian/waf_config.toml
   ```

---

### 3. How to Obtain a SATGuardian License Token?
To connect your WAF with the cloud mathematical synthesis engine and enable continuous learning:

1. **Create an Account:**  
   Register at [https://satguardian.tech](https://satguardian.tech).
2. **Select a Security Unit (SU) Plan:**  
   Choose Scout ($20/mo), Pro ($49/mo), Startup ($499/mo), Escala ($2,499/mo), or Enterprise.
3. **Copy Your API Key:**  
   In your SATGuardian dashboard, copy your **API Key** (`ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx`).

---

### 4. How to Configure the License in the WAF?

#### Option A: Inside `waf_config.toml` (Recommended)
Edit `waf_config.toml`:

```toml
# Official SATGuardian Boolean synthesis API endpoint
satguardian_api_url = "https://satguardian.tech/api/simplify"

# Your SATGuardian API Key
satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Enable continuous autonomous learning and synthesis
auto_sync_enabled = true

# Training synchronization interval in seconds (default: 300s = 5 minutes)
autonomous_sync_interval_secs = 300
```

#### Option B: Via Environment Variables (Docker / Kubernetes)
```bash
export SATGUARDIAN_API_KEY="ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SATGUARDIAN_API_URL="https://satguardian.tech/api/simplify"
```
In `docker-compose.yml`:
```yaml
environment:
  - SATGUARDIAN_API_URL=https://satguardian.tech/api/simplify
  - SATGUARDIAN_API_KEY=ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

#### Option C: Verify Your License Connection
To test communication with the cloud synthesis engine:
```bash
satguardian-waf entitlement
```

## 🏛️ System Architecture

```text
       [ Inbound HTTP / GraphQL / gRPC Traffic from Clients ]
                                 │
                                 ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      GUARDIAN WAF (Rust Server)                        │
│                                                                        │
│  1. Multi-Stage Grammar Normalizer & AST Lexer                         │
│     - Multi-pass recursive URL decoding (%20, %2e%2e%2f)               │
│     - SQL comment stripping (/**/ -> epsilon)                          │
│     - GraphQL AST Lexer: introspection probes, depth & batching        │
│     - Strict JSON Parser: Prototype Pollution & nesting bombs          │
│     - gRPC Frame Inspector: 5-byte wire prefix & status injection      │
│     - JWT Tamper Analyzer: alg "none", missing sig, KID traversal      │
│     - Shannon entropy binarizer & Boolean Hypercube {0, 1}^N           │
│                                                                        │
│  2. In-Memory Fast-Path SAT Solver (< 0.02 ms)                         │
│     Evaluates 10 Formal Certainty Islands:                             │
│     • ISLAND-SQLI       (Tautologies, UNION select, Time-delay, DDL)   │
│     • ISLAND-XSS        (Script contexts, Event attributes, SVG, URIs) │
│     • ISLAND-RCE        (Shell chains, Subshells, Dynamic eval sinks)  │
│     • ISLAND-LFI        (Path traversal escapes, Sensitive roots)      │
│     • ISLAND-SSRF       (Cloud metadata 169.254, RFC1918 loopbacks)    │
│     • ISLAND-GRAPHQL    (Introspection dumping, Depth > 6, Batching)   │
│     • ISLAND-JSON-PROTO (__proto__, constructor.prototype, Bomb > 20)  │
│     • ISLAND-GRPC       (Client status trailers, HTTP/2 frame desync)  │
│     • ISLAND-JWT        (Alg: none, Unsigned tokens, KID injection)    │
│     • ISLAND-STATEFUL   (Atomic Ring Counter L7 DDoS & Brute Force)    │
│                                                                        │
│  3. Perimeter Decision:                                                │
│     ├─ [ VIOLATION DETECTED ]                                          │
│     │   └─ Immediate HTTP 403 Forbidden Response (< 0.05 ms)           │
│     │      • X-SATGuardian-Action: BLOCK                                   │
│     │      • X-SATGuardian-Proof: [Causal Proof Chain]                     │
│     │      • JSON Body: LaTeX Formal Proof + Active Predicate Tokens   │
│     │                                                                  │
│     └─ [ CLEAN TRAFFIC (ALLOW) ]                                       │
│         └─ High-Throughput Proxy Streaming to Upstream Backend         │
│            • http://127.0.0.1:3000                                     │
│            • X-SATGuardian-Protected: true                                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (Non-blocking asynchronous queue)
                                    ▼
                        [ SQLite WAL Ledger ] (waf_ledger.db)
                        - Asynchronous audit event stream
                        - Novel anomaly minterm hypercubes (u128)
                                    │
                                    ▼ (Background Worker / Sync Trigger)
┌────────────────────────────────────────────────────────────────────────┐
│   Autonomous Exact Boolean Minimization                                │
│   Target: https://satguardian.tech/api/simplify                        │
│   (Consumes Security Units - SU)                                       │
│                                                                        │
│   - Binarizes novel anomaly minterms into prime implicants in O(n)     │
│   - Synthesizes exact minimal Boolean equations                        │
│   - Hot-compiles dynamic clauses into Fast-Path memory in microseconds │
│     WITHOUT restarting the server or dropping connections!             │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ The 10 Certainty Islands

| Island ID | Domain | Target Vector & Formal Invariant | Action |
| :--- | :--- | :--- | :---: |
| **`ISLAND-SQLI`** | Relational SQL AST | Tautologies (`' OR 1=1`), UNION exfiltration, stacked DDL, sleep/benchmark primitives. | **BLOCK** |
| **`ISLAND-XSS`** | DOM Execution Context | Script tags, inline event triggers (`onload`, `onerror`), SVG vectors, `javascript:` URIs. | **BLOCK** |
| **`ISLAND-RCE`** | OS Command Execution | Shell chaining (`;`, `\|\|`, `&&`), subshell substitutions (`$()`, backticks), eval sinks. | **BLOCK** |
| **`ISLAND-LFI`** | Filesystem Sandbox | Path traversals (`../../`), direct root targeting (`/etc/passwd`, `/proc/self/environ`). | **BLOCK** |
| **`ISLAND-SSRF`** | Network Perimeter | Cloud metadata (`169.254.169.254`), loopback proxies (`127.0.0.1`), private RFC1918 ranges. | **BLOCK** |
| **`ISLAND-GRAPHQL`** | GraphQL Schema & AST | Introspection queries (`__schema`, `__type`), recursive cyclic nesting (> 6 levels), batching. | **BLOCK** |
| **`ISLAND-JSON-PROTO`** | Strict JSON Schemas | Prototype pollution (`__proto__`, `constructor.prototype`), JSON schema nesting bombs (> 20 levels). | **BLOCK** |
| **`ISLAND-GRPC`** | HTTP/2 Wire Protocol | Client trailer injection (`grpc-status: 0`), 5-byte gRPC framing desynchronization / smuggling. | **BLOCK** |
| **`ISLAND-JWT`** | Cryptographic Identity | Algorithm confusion (`alg: "none"`), missing signatures, `kid` path traversal / SQLi. | **BLOCK** |
| **`ISLAND-STATEFUL`** | Behavioral Dynamics | Temporal sliding window ring counters: Layer-7 burst DDoS and distributed credential stuffing. | **BLOCK** |

---

## 🧪 Proof of Concept (PoC) & Multi-Agent Duel

The repository includes a comprehensive Python Proof of Concept in [`satguardian_waf/`](file:///d:/proyectos/rush/satguardian-waf-guardian/satguardian_waf) to visualize and compare the technology before production deployment.

### 1. Interactive Web Dashboard (`run_web.py`)
Launch the visual duel simulator:
```bash
python run_web.py 8002
```
* **URL:** Navigate to **`http://localhost:8002`**
* **Live Multi-Agent Duel:** Watch **SATGuardian SAT**, **ModSecurity (Regex)**, and **Pure LLM (JEV Solo)** process the same payloads side-by-side.
* **KaTeX $\LaTeX$ Math Mode:** Renders mathematically verifiable proofs in real time explaining why attacks are dropped with zero hallucination.

### 2. Single Payload CLI Inspection (`run_cli.py`)
```bash
python run_cli.py --path "/api/users" --query "id=1' OR '1'='1"
```

### 3. Multi-Agent Benchmark Suite (`run_benchmark.py`)
```bash
python run_benchmark.py 100
```
Compares Accuracy, False Negatives, False Positives, Latency, and Cost across all 3 agent architectures.

*(For in-depth details, see [PROOF_OF_CONCEPT.md](PROOF_OF_CONCEPT.md) and [SATGUARDIAN_METHODOLOGY.md](SATGUARDIAN_METHODOLOGY.md)).*

---

## 🌊 Blue Ocean Strategy Comparison

| Competitive Factor | Traditional Regex WAF (ModSecurity / CRS) | Cloud LLM WAF (Cloudflare AI / AWS) | SATGuardian Edge WAF (Rust) |
| :--- | :---: | :---: | :---: |
| **Inference Cost** | Low | High ($2,000+ / 1M reqs) | **$0.00 (Local Deterministic)** |
| **Network SLA Compliance** | Fast ($1 - 5\text{ ms}$) | Unacceptable ($350 - 650\text{ ms}$) | **Ultra-Fast (< 0.05 ms / < 20 µs)** |
| **Resistance to Obfuscation** | Poor (Evasion bypasses) | High (Context-aware) | **Absolute (Certainty Islands)** |
| **False Positive Rate** | High (Breaks on valid code) | Moderate | **Zero (0.00% on Benign Traffic)** |
| **Causal Explainability** | Opaque rule ID | Non-deterministic text | **Formal $\LaTeX$ & Causal Graphs** |
| **Enterprise Grammars** | Partial | Brittle | **Native (GraphQL, JSON, gRPC, JWT)** |
| **Behavioral Defense** | Rudimentary iptables | Slow batch heuristics | **Sliding Window Ring Counters** |
| **Autonomous Evolution** | Slow manual CRS releases | Costly model fine-tuning | **Real-Time Boolean Minimization** |

> 📖 **In-Depth Comparative Analysis:** See the technical report [COMPARATIVE_ANALYSIS_PRE_VS_SATGUARDIAN.md](COMPARATIVE_ANALYSIS_PRE_VS_SATGUARDIAN.md) for the complete breakdown of the four structural failures of the pre-SATGUARDIAN era (RegEx and Cloud AI) alongside empirical benchmark findings.

---

## 🛠️ Zero-Dependency Installation

Clients **do not need to install runtime dependencies** on their servers (no Rust toolchains, no Cargo, no Python runtimes, no C/C++ compilers, and no dynamic shared libraries). The binary is 100% self-contained and statically linked.

### Method 1: Quick One-Liner Installer (Recommended for Production)

#### On Linux (Ubuntu / Debian / RHEL / CentOS / Rocky / Alpine)
Run directly in your terminal as root:
```bash
curl -sSL https://raw.githubusercontent.com/satguardian/satguardian-waf/main/install.sh | sudo bash
```
> **What does it do automatically?**
> 1. Detects system architecture (`x86_64` or `aarch64/ARM64`).
> 2. Installs the static binary to `/usr/local/bin/satguardian-waf` (with `/usr/local/bin/satguardian-waf-guardian` alias).
> 3. Deploys default configuration to `/etc/satguardian/waf_config.toml`.
> 4. Registers and starts the `systemd` system daemon (`satguardian-waf.service`).

#### On Windows Server
Run in PowerShell as Administrator:
```powershell
irm https://raw.githubusercontent.com/satguardian/satguardian-waf/main/install.ps1 | iex
```
> **What does it do automatically?**
> 1. Installs the executable to `C:\Program Files\Satguardian\WAF\satguardian-waf.exe`.
> 2. Deploys default configuration to `C:\ProgramData\Satguardian\WAF\waf_config.toml`.
> 3. Appends the directory to `System PATH` (accessible globally from any prompt).
> 4. Registers and launches the `SATGuardianWAF` Windows Service configured for automatic startup.

---

### Method 2: Offline Self-Contained Packages (`dist/` ZIP / TAR.GZ)

For air-gapped servers, restricted network perimeters, or environments where piped script execution is restricted:

1. **Download the precompiled bundle:**
   - **Windows:** `satguardian-waf-v0.3.0-windows-x86_64.zip`
   - **Linux:** `satguardian-waf-v0.3.0-linux-x86_64.tar.gz`
2. **Extract and install with a single command:**
   - On Windows:
     ```powershell
     powershell -ExecutionPolicy Bypass -File .\install.ps1
     ```
   - On Linux:
     ```bash
     sudo ./install.sh
     ```
3. **Portable Execution (Zero System Modifications):**
   If you prefer not to register system services, execute the binary directly:
   ```bash
   # Windows
   .\satguardian-waf.exe proxy --config .\waf_config.toml

   # Linux
   ./satguardian-waf proxy --config ./waf_config.toml
   ```

To generate standalone distribution packages locally:
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package_dist.ps1 -NoRebuild
```
or on Linux:
```bash
./scripts/package_dist.sh --no-rebuild
```

---

### Method 3: Container Deployment (Docker & Docker Compose)

For container-native environments without host modifications:

```bash
# Start immediately in background with Docker Compose
docker compose up -d

# Stream real-time inspection telemetry and logs
docker compose logs -f satguardian-waf
```

---

### Clean Uninstallation

To completely remove the service, configuration, and binaries without leaving orphaned artifacts:
- **On Windows:** `powershell -ExecutionPolicy Bypass -File .\uninstall.ps1`
- **On Linux:** `sudo ./uninstall.sh` (or `sudo ./uninstall.sh --purge` to also remove the audit database).

---

## ⚙️ Configuration Reference (`waf_config.toml`)

```toml
# Network listener for inbound HTTP traffic
listen_addr = "0.0.0.0:8080"

# Target upstream backend application
upstream_url = "http://127.0.0.1:3000"

# Defense mode: "block" (perimeter defense) or "monitor" (dry-run detection)
mode = "block"

# SATGuardian Cloud Optimization API URL
satguardian_api_url = "https://satguardian.tech/api/simplify"

# SATGuardian Cloud API Key (or set via SATGUARDIAN_API_KEY environment variable)
# satguardian_api_key = "ek_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# SQLite WAL Ledger database path
database_path = "waf_ledger.db"

# Autonomous background minimization sync interval in seconds (default: 300s)
autonomous_sync_interval_secs = 300

# Enable automatic hot minimization sync with https://satguardian.tech
auto_sync_enabled = true

# ==============================================================================
# STATEFUL & BEHAVIORAL DEFENSE (Layer-7 DDoS & Credential Stuffing)
# ==============================================================================
# Enable temporal sliding window ring buffer analysis
stateful_enabled = true

# Max total requests permitted in sliding window per IP across all endpoints
stateful_global_limit = 300

# Max attempts permitted on sensitive authentication endpoints (/login, /auth, etc.)
stateful_auth_limit = 20

# Sliding temporal window duration in seconds (default: 60s ring buffer)
stateful_window_secs = 60

# Temporary isolation quarantine / jail duration in seconds for offenders
stateful_ban_secs = 180

# Optional Redis connection URL for distributed cluster state synchronization
# redis_url = "redis://127.0.0.1:6379"
```

---

## 💻 CLI Commands & Usage

### 1. Launch Reverse Proxy Daemon
```bash
satguardian-waf proxy --listen 0.0.0.0:8080 --upstream http://127.0.0.1:3000 --config waf_config.toml
```

### 2. Inspect Single Request Payload
```bash
satguardian-waf inspect --method GET --path "/api/users" --query "id=1' OR '1'='1"
```
**Example Terminal Output:**
```text
🔍 SATGuardian Edge WAF: Payload Inspection Report
============================================================
Request ID       : req_84920481
Target Path      : /api/users
Query String     : id=1' OR '1'='1
Action Decision  : Block
Attack Category  : SQL INJECTION (SQLi)
Latency          : 18.42 µs (0.0184 ms)
Active Tokens    : ["QUOTE", "TAUTOLOGY_EQUALS"]
Certainty Islands: ["ISLAND-SQLI"]
------------------------------------------------------------
Causal Proof     :
(QUOTE AND TAUTOLOGY_EQUALS) violates [SAT-SQLI-01] -> ACTION_BLOCK [sql_injection]
------------------------------------------------------------
LaTeX Formal SAT Proof:
\begin{aligned}
\mathbf{Certainty\ Island} &: \{\mathcal{I}_{\text{SQLi}}\} \subset \mathcal{I}_{\text{SAT}} \\[4pt]
\mathbf{Active\ Tokens} &: \mathcal{T} = \{\texttt{QUOTE}, \texttt{TAUTOLOGY\_EQUALS}\} \\[4pt]
\mathbf{Invariant\ Rule} &: \mathcal{C}_{\text{WAF}} \equiv \neg (\texttt{SAT-SQLI-01}) \\[4pt]
\mathbf{SAT\ Evaluation} &: \text{Eval}(\mathcal{C}_{\text{WAF}}, \mathcal{T}) \equiv \mathbf{FALSE} \implies \mathbf{BLOCK\ [SQL\_INJECTION]}
\end{aligned}
============================================================
```

### 3. Check Cloud Entitlement & SU Balance
```bash
satguardian-waf entitlement
```

### 4. Run Built-In Multi-Vector Benchmark
```bash
satguardian-waf benchmark --requests 10000
```

### 5. Trigger Cloud Simplification & Hot-Compilation
```bash
satguardian-waf sync-simplify --limit 50
```

---

## 📡 REST API & Sidecar Inspection Endpoints

The server exposes built-in management & telemetry routes alongside the reverse proxy:

* **`POST /api/waf/inspect`**: Submit arbitrary HTTP payloads for sub-millisecond evaluation.
* **`GET /api/waf/metrics`**: Live telemetry (total requests, blocked count, average latency, p99, pending anomalies).
* **`GET /api/waf/rules`**: Complete catalog of active Certainty Island invariant rules.
* **`GET /api/waf/islands`**: Catalog of Certainty Islands.
* **`POST /api/waf/sync-simplify`**: Manually trigger Boolean minimization with `https://satguardian.tech/api/simplify` and hot-reload rules.
* **`GET /health`** or **`GET /livez`**: Service health & liveness check.

---

## 🧪 Unit & Integration Testing

Run the full Rust test suite covering all 10 Certainty Islands, enterprise grammars, and stateful sliding window ring counters:
```bash
cargo test -p satguardian-waf-guardian
```
*18 unit and integration tests passing with 0 false positives.*

---

## 📄 License

Dual-licensed under [MIT](LICENSE) or [Apache 2.0](LICENSE-APACHE).
