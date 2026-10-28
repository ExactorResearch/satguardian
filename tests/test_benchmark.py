"""Tests for WAF Benchmark Runner."""

import pytest
from satguardian_waf.benchmark.runner import WAFBenchmarkRunner
from satguardian_waf.benchmark.reporter import generate_ascii_table, generate_markdown_report


def test_benchmark_runner_execution():
    runner = WAFBenchmarkRunner()
    result = runner.run_benchmark(num_requests=20, attack_ratio=0.5, seed=42)
    
    assert result.dataset_size == 20
    assert len(result.agent_metrics) == 3
    
    sat_metrics = next(m for k, m in result.agent_metrics.items() if "SATGuardian" in k or "Exactor" in k)
    assert sat_metrics.total_requests == 20
    assert sat_metrics.accuracy >= 0.90
    assert sat_metrics.total_cost_usd == 0.0

    ascii_table = generate_ascii_table(result)
    assert "SATGUARDIAN" in ascii_table

    md_report = generate_markdown_report(result)
    assert "SATGuardian" in md_report
