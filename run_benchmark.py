#!/usr/bin/env python3
"""Run SATGuardian Edge WAF Benchmark Suite."""

import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from satguardian_waf.benchmark.runner import WAFBenchmarkRunner
from satguardian_waf.benchmark.reporter import generate_ascii_table, generate_markdown_report


def main():
    samples = 100
    if len(sys.argv) > 1:
        try:
            samples = int(sys.argv[1])
        except ValueError:
            pass

    print("\n" + "=" * 80)
    print(f" [BENCHMARK] Starting SATGUARDIAN EDGE WAF Evaluation ({samples} reqs)...")
    print("=" * 80 + "\n")

    runner = WAFBenchmarkRunner()
    result = runner.run_benchmark(num_requests=samples)

    print(generate_ascii_table(result))
    print("\n[INFO] Markdown Summary:")
    print(generate_markdown_report(result))


if __name__ == "__main__":
    main()
