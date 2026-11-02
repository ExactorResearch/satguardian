"""Benchmark Reporter for ASCII and Markdown Output.

Reports are intentionally framed as Python stand-in comparisons. Only the
SATGuardian row is this project's code; the others are local reimplementations
and are not measurements of the named products.
"""

from __future__ import annotations

from satguardian_waf.benchmark.runner import BenchmarkSuiteResult


def _provenance_lines(result: BenchmarkSuiteResult) -> list[str]:
    lines = ["SCOPE AND PROVENANCE:"]
    lines.append(f"  Dataset: {result.dataset_provenance}")
    lines.append("  Agents:")
    for name, provenance in result.agent_provenance.items():
        lines.append(f"    - {name}: {provenance}")
    lines.append(f"  Disclaimer: {result.disclaimer}")
    return lines


def generate_ascii_table(result: BenchmarkSuiteResult) -> str:
    """Formats benchmark results as an ASCII comparison table."""
    lines = []
    lines.append("=" * 108)
    lines.append(
        f"  SATGUARDIAN EDGE WAF: PYTHON STAND-IN COMPARISON "
        f"(Samples: {result.dataset_size}, Attack Ratio: {result.attack_ratio*100:.0f}%)"
    )
    lines.append("=" * 108)
    header = f"{'Agent / Architecture':<44} | {'Accuracy':<9} | {'Avg Lat':<10} | {'P99 Lat':<10} | {'FPR':<6} | {'FNR':<6} | {'$/1M Req':<9}"
    lines.append(header)
    lines.append("-" * 108)

    for name, m in result.agent_metrics.items():
        short_name = name[:43]
        row = (
            f"{short_name:<44} | "
            f"{m.accuracy*100:>7.1f}% | "
            f"{m.avg_latency_ms:>8.4f}ms | "
            f"{m.p99_latency_ms:>8.4f}ms | "
            f"{m.false_positive_rate*100:>5.1f}% | "
            f"{m.false_negative_rate*100:>5.1f}% | "
            f"${m.cost_per_million_usd:>7.2f}"
        )
        lines.append(row)

    lines.append("=" * 108)
    if result.summary_insights:
        lines.append("MEASURED OBSERVATIONS (not vendor comparisons):")
        for ins in result.summary_insights:
            clean_ins = ins.replace("**", "")
            lines.append(f"  * {clean_ins}")
        lines.append("=" * 108)

    lines.extend(_provenance_lines(result))
    lines.append("=" * 108)

    return "\n".join(lines)


def generate_markdown_report(result: BenchmarkSuiteResult) -> str:
    """Formats benchmark results as a GitHub Markdown table."""
    lines = []
    lines.append("## SATGuardian Edge WAF - Python Stand-In Benchmark\n")
    lines.append(
        f"Evaluated on **{result.dataset_size} in-repo, in-sample HTTP requests**. "
        "Only the SATGuardian row is this project's code; all other rows are local "
        "Python stand-ins, not the named products.\n"
    )
    lines.append("| Agent / Architecture | Accuracy | Avg Latency | P99 Latency | False Positive Rate | False Negative Rate | Cost / 1M Requests |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")

    for name, m in result.agent_metrics.items():
        lines.append(
            f"| **{name}** | {m.accuracy*100:.1f}% | `{m.avg_latency_ms:.4f} ms` | `{m.p99_latency_ms:.4f} ms` | {m.false_positive_rate*100:.1f}% | {m.false_negative_rate*100:.1f}% | **${m.cost_per_million_usd:.2f}** |"
        )

    lines.append("\n### Measured Observations\n")
    for ins in result.summary_insights:
        lines.append(f"- {ins}")

    lines.append("\n### Scope and Provenance\n")
    lines.append(f"- **Dataset:** {result.dataset_provenance}")
    for name, provenance in result.agent_provenance.items():
        lines.append(f"- **{name}:** {provenance}")
    lines.append(f"- **Disclaimer:** {result.disclaimer}")

    return "\n".join(lines)
