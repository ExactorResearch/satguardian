"""Benchmark Runner for Multi-Agent WAF Evaluation."""

from __future__ import annotations

from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory
from satguardian_waf.core.dataset import get_benchmark_dataset, generate_synthetic_attack_stream
from satguardian_waf.agents.base import BaseWAFAgent
from satguardian_waf.agents.satguardian_agent import SatguardianWAFAgent, ExactorWAFAgent
from satguardian_waf.agents.jev_pure_agent import PureJEVAgent
from satguardian_waf.agents.regex_baseline_agent import RegexBaselineAgent
from satguardian_waf.agents.coraza_agent import CorazaWAFAgent
from satguardian_waf.agents.safeline_agent import SafeLineWAFAgent
from satguardian_waf.agents.docker_http_agent import DockerHTTPWAFAgent
from satguardian_waf.benchmark.metrics import compute_metrics, AgentBenchmarkMetrics


@dataclass
class BenchmarkSuiteResult:
    """Overall results of a benchmark run across multiple agents."""
    dataset_size: int
    attack_ratio: float
    agent_metrics: Dict[str, AgentBenchmarkMetrics] = field(default_factory=dict)
    summary_insights: List[str] = field(default_factory=list)


class WAFBenchmarkRunner:
    """Orchestrates benchmark runs on curated and synthetic HTTP attack streams."""

    def __init__(self, agents: Optional[List[BaseWAFAgent]] = None):
        if agents is None:
            self.agents: List[BaseWAFAgent] = [
                SatguardianWAFAgent(),
                SafeLineWAFAgent(),
                CorazaWAFAgent(),
                RegexBaselineAgent(),
                PureJEVAgent()
            ]
        else:
            self.agents = agents

    def run_benchmark(
        self,
        num_requests: int = 100,
        attack_ratio: float = 0.5,
        seed: int = 42,
        progress_cb: Optional[Callable[[int, int, str], None]] = None
    ) -> BenchmarkSuiteResult:
        """Executes a benchmark run across all registered agents."""
        if num_requests == len(get_benchmark_dataset()):
            dataset = get_benchmark_dataset()
        else:
            dataset = generate_synthetic_attack_stream(num_requests=num_requests, attack_ratio=attack_ratio, seed=seed)

        ground_truth = [req.expected_category for req in dataset]
        agent_metrics: Dict[str, AgentBenchmarkMetrics] = {}

        for agent in self.agents:
            decisions = []
            for i, req in enumerate(dataset):
                dec = agent.inspect(req)
                decisions.append(dec)
                if progress_cb:
                    progress_cb(i + 1, len(dataset), agent.name)

            metrics = compute_metrics(agent.name, decisions, ground_truth)
            agent_metrics[agent.name] = metrics

        # Generate empirical comparative insights
        insights = []
        satguardian_m = next((m for k, m in agent_metrics.items() if "SATGuardian" in k or "Exactor" in k), None)
        safeline_m = next((m for k, m in agent_metrics.items() if "SafeLine" in k), None)
        coraza_m = next((m for k, m in agent_metrics.items() if "Coraza" in k), None)
        jev_m = next((m for k, m in agent_metrics.items() if "Probabilistic" in k or "JEV" in k), None)
        regex_m = next((m for k, m in agent_metrics.items() if "Regex" in k), None)

        if satguardian_m and coraza_m and satguardian_m.avg_latency_ms > 0:
            coraza_speedup = round(coraza_m.avg_latency_ms / satguardian_m.avg_latency_ms, 2)
            insights.append(
                f"🚀 SATGuardian evaluated payloads **{coraza_speedup}x faster** than Coraza OWASP CRS v4 "
                f"({satguardian_m.avg_latency_ms:.4f} ms vs. {coraza_m.avg_latency_ms:.4f} ms avg CPU time)."
            )

        if satguardian_m and regex_m:
            fnr_diff = round((regex_m.false_negative_rate - satguardian_m.false_negative_rate) * 100, 1)
            insights.append(
                f"🛡️ SATGuardian reduced false negatives by **{fnr_diff} percentage points** compared to Classical ModSecurity Regex "
                f"(FNR: {satguardian_m.false_negative_rate * 100:.1f}% vs. {regex_m.false_negative_rate * 100:.1f}%)."
            )

        if satguardian_m and jev_m:
            fpr_diff = round((jev_m.false_positive_rate - satguardian_m.false_positive_rate) * 100, 1)
            insights.append(
                f"🎯 SATGuardian reduced false positives on benign technical traffic by **{fpr_diff} percentage points** "
                f"compared to Probabilistic Token Scoring (FPR: {satguardian_m.false_positive_rate * 100:.1f}% vs. {jev_m.false_positive_rate * 100:.1f}%)."
            )

        return BenchmarkSuiteResult(
            dataset_size=len(dataset),
            attack_ratio=attack_ratio,
            agent_metrics=agent_metrics,
            summary_insights=insights
        )
