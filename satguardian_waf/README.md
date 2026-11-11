# SATGuardian Edge WAF: Python Proof of Concept (PoC)

This directory contains the Python reference implementation and interactive demonstration
suite of the **SATGuardian Edge WAF**. It is the Python reference implementation
used to explore the model; the enforcement path that ships is the Rust engine in `src/`.

## Quick Start

### 1. Web Dashboard & Multi-Agent Duel Simulator
```bash
python ../run_web.py 8002
```
Navigate to `http://localhost:8002` for the live duel simulator. Its three lanes are
**local Python stand-ins written for this repository**, not vendor products or models:
the SAT lane is a Python reimplementation (not the native Rust engine), the Regex lane is
a hand-written baseline (not ModSecurity or the CRS), and the "Pure LLM" lane is a
hand-written Python stand-in with heuristics coded by hand — **no LLM, no trained model
and no inference call runs in that lane**. Results are in-sample demonstrations.

### 2. Single Payload CLI Inspection
```bash
python ../run_cli.py --path "/api/v1/search" --query "id=1' OR '1'='1"
```

### 3. Multi-Agent Benchmark
```bash
python ../run_benchmark.py 100
```
Benchmarks the same local stand-ins against the small in-repo payload list. It is not a
comparison against Coraza, SafeLine or ModSecurity.

For complete documentation, architecture, and empirical findings, see the root [PROOF_OF_CONCEPT.md](../PROOF_OF_CONCEPT.md).
For the Rust reverse proxy server, refer to the root [README.md](../README.md).
