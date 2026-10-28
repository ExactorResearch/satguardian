# Guardian WAF: Python Proof of Concept (PoC)

This directory contains the Python reference implementation and interactive demonstration suite of the **Guardian WAF**.

## Quick Start

### 1. Web Dashboard & Multi-Agent Duel Simulator
```bash
python ../run_web.py 8002
```
Navigate to `http://localhost:8002` to interact with the live duel simulator (SATGuardian SAT vs. Regex Baseline vs. Pure LLM).

### 2. Single Payload CLI Inspection
```bash
python ../run_cli.py --path "/api/v1/search" --query "id=1' OR '1'='1"
```

### 3. Multi-Agent Benchmark
```bash
python ../run_benchmark.py 100
```

For complete documentation, architecture, and empirical findings, see the root [PROOF_OF_CONCEPT.md](../PROOF_OF_CONCEPT.md).
For the production-grade Rust reverse proxy server, refer to the root [README.md](../README.md).
