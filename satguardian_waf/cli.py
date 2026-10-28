"""Interactive CLI for SATGuardian Edge WAF."""

from __future__ import annotations

import sys
import argparse

# Enable UTF-8 console output for Windows PowerShell / CMD
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory
from satguardian_waf.core.dataset import get_benchmark_dataset
from satguardian_waf.agents.satguardian_agent import SatguardianWAFAgent, ExactorWAFAgent
from satguardian_waf.agents.jev_pure_agent import PureJEVAgent
from satguardian_waf.agents.regex_baseline_agent import RegexBaselineAgent
from satguardian_waf.benchmark.runner import WAFBenchmarkRunner
from satguardian_waf.benchmark.reporter import generate_ascii_table


def run_single_inspection(path: str, query: str, body: str, method: str = "GET"):
    """Inspects a custom HTTP payload across SATGuardian, Pure JEV, and Regex."""
    req = HTTPRequestPayload(
        method=method,
        path=path,
        query_string=query,
        body=body,
        expected_category=AttackCategory.UNKNOWN
    )

    print("\n" + "=" * 80)
    print(" [SHIELD] SATGUARDIAN EDGE WAF - SINGLE PAYLOAD TRIAGE")
    print("=" * 80)
    print(f" Request: {method} {path}?{query}")
    if body:
        print(f" Body   : {body}")
    print("-" * 80)

    agents = [SatguardianWAFAgent(), RegexBaselineAgent(), PureJEVAgent()]
    for agent in agents:
        decision = agent.inspect(req)
        status = "[BLOCKED]" if decision.is_blocked else "[ALLOWED]"
        print(f"\n[{agent.name}]")
        print(f"  Decision   : {status} ({decision.predicted_category.value})")
        print(f"  Latency    : {decision.latency_ms:.3f} ms")
        print(f"  Cost (USD) : ${decision.cost_usd:.4f}")
        print(f"  Explanation: {decision.explanation}")
        if decision.proof_latex:
            print(f"  SAT Proof  : {decision.proof_latex[:90]}...")

    print("\n" + "=" * 80)


def main():
    parser = argparse.ArgumentParser(description="SATGuardian Edge WAF CLI & Benchmark")
    parser.add_argument("--benchmark", action="store_true", help="Run multi-agent comparative benchmark")
    parser.add_argument("--samples", type=int, default=100, help="Number of samples for benchmark")
    parser.add_argument("--path", type=str, default="/api/v1/search", help="Target request path")
    parser.add_argument("--query", type=str, default="id=1' UNION SELECT username,password FROM users--", help="Target query string")
    parser.add_argument("--body", type=str, default="", help="Target request body")
    parser.add_argument("--method", type=str, default="GET", help="HTTP Method")

    args = parser.parse_args()

    if args.benchmark:
        print(f"Running SATGuardian Edge WAF Benchmark ({args.samples} requests)...")
        runner = WAFBenchmarkRunner()
        res = runner.run_benchmark(num_requests=args.samples)
        print(generate_ascii_table(res))
    else:
        run_single_inspection(args.path, args.query, args.body, args.method)


if __name__ == "__main__":
    main()
