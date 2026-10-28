"""Benchmark Reporter for ASCII and Markdown Output."""

from __future__ import annotations

from typing import Dict
from satguardian_waf.benchmark.metrics import AgentBenchmarkMetrics
from satguardian_waf.benchmark.runner import BenchmarkSuiteResult


def generate_ascii_table(result: BenchmarkSuiteResult) -> str:
    """Formats benchmark results as an ASCII comparison table."""
    lines = []
    lines.append("=" * 105)
    lines.append(f"  SATGUARDIAN EDGE WAF BENCHMARK RESULTS (Samples: {result.dataset_size}, Attack Ratio: {result.attack_ratio*100:.0f}%)")
    lines.append("=" * 105)
    header = f"{'Agent / Architecture':<35} | {'Accuracy':<9} | {'Avg Lat':<9} | {'P99 Lat':<9} | {'FPR':<6} | {'FNR':<6} | {'$/1M Req':<10}"
    lines.append(header)
    lines.append("-" * 105)

    for name, m in result.agent_metrics.items():
        short_name = name[:34]
        row = (
            f"{short_name:<35} | "
            f"{m.accuracy*100:>7.1f}% | "
            f"{m.avg_latency_ms:>7.3f}ms | "
            f"{m.p99_latency_ms:>7.2f}ms | "
            f"{m.false_positive_rate*100:>5.1f}% | "
            f"{m.false_negative_rate*100:>5.1f}% | "
            f"${m.cost_per_million_usd:>8.2f}"
        )
        lines.append(row)

    lines.append("=" * 105)
    if result.summary_insights:
        lines.append("KEY INSIGHTS & ARCHITECTURAL VERDICTS:")
        for ins in result.summary_insights:
            # strip markdown bold for clean CLI
            clean_ins = ins.replace("**", "")
            lines.append(f"  * {clean_ins}")
        lines.append("=" * 105)

    return "\n".join(lines)


def generate_markdown_report(result: BenchmarkSuiteResult) -> str:
    """Formats benchmark results as a GitHub Markdown table."""
    lines = []
    lines.append("## 🛡️ SATGuardian Edge WAF - Benchmark Comparison Matrix\n")
    lines.append(f"Evaluated on **{result.dataset_size} HTTP requests** across real-world OWASP Top 10 attack vectors and benign enterprise traffic.\n")
    lines.append("| Agent / Architecture | Accuracy | Avg Latency | P99 Latency | False Positive Rate | False Negative Rate | Cost / 1M Requests |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    for name, m in result.agent_metrics.items():
        lines.append(
            f"| **{name}** | {m.accuracy*100:.1f}% | `{m.avg_latency_ms:.3f} ms` | `{m.p99_latency_ms:.2f} ms` | {m.false_positive_rate*100:.1f}% | {m.false_negative_rate*100:.1f}% | **${m.cost_per_million_usd:.2f}** |"
        )

    lines.append("\n### 💡 Key Findings\n")
    for ins in result.summary_insights:
        lines.append(f"- {ins}")

    return "\n".join(lines)
