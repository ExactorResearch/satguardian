"""Benchmark Runner for Multi-Agent WAF Evaluation.

Scope warning: this harness compares the Python reference implementation against
Python stand-ins written for this repository. It does not execute Coraza,
SafeLine, ModSecurity, or any other vendor engine. Numbers produced here must be
presented as stand-in comparisons, never as vendor or independent benchmarks.
"""

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


DATASET_PROVENANCE = (
    "In-repo payload list in satguardian_waf/core/dataset.py, sampled with a fixed "
    "seed. It is small, hand-written, and was used during development, so results "
    "are in-sample. It is not a held-out corpus or a third-party dataset."
)

BENCHMARK_DISCLAIMER = (
    "Every non-SATGuardian row is a Python reimplementation of a technique, not the "
    "actual product. Rows are labelled 'stand-in' and must not be cited as Coraza, "
    "SafeLine, ModSecurity, or vendor benchmarks. The SATGuardian row is the Python "
    "reference port, not the native Rust engine. Small in-sample datasets do not "
    "support quality or production-readiness claims."
)


@dataclass
class BenchmarkSuiteResult:
    """Overall results of a benchmark run across multiple agents."""
    dataset_size: int
    attack_ratio: float
    agent_metrics: Dict[str, AgentBenchmarkMetrics] = field(default_factory=dict)
    summary_insights: List[str] = field(default_factory=list)
    dataset_provenance: str = DATASET_PROVENANCE
    disclaimer: str = BENCHMARK_DISCLAIMER
    agent_provenance: Dict[str, str] = field(default_factory=dict)


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

        insights = self._build_insights(agent_metrics)
        agent_provenance = {agent.name: agent.provenance for agent in self.agents}

        return BenchmarkSuiteResult(
            dataset_size=len(dataset),
            attack_ratio=attack_ratio,
            agent_metrics=agent_metrics,
            summary_insights=insights,
            agent_provenance=agent_provenance,
        )

    @staticmethod
    def _build_insights(agent_metrics: Dict[str, AgentBenchmarkMetrics]) -> List[str]:
        """Reports measured values without implying vendor or real-product comparisons."""
        insights: List[str] = [
            "All rows were measured on the same in-repo, in-sample request stream."
        ]

        satguardian_m = next(
            (m for k, m in agent_metrics.items() if "SATGuardian" in k or "Exactor" in k),
            None,
        )
        if satguardian_m:
            insights.append(
                f"SATGuardian Python reference: {satguardian_m.accuracy * 100:.1f}% accuracy, "
                f"{satguardian_m.avg_latency_ms:.4f} ms mean in-process CPU time. "
                "This is the Python port; the native Rust engine is not measured here."
            )

        if agent_metrics:
            fastest = min(agent_metrics.values(), key=lambda m: m.avg_latency_ms)
            insights.append(
                f"Fastest Python agent on this stream: {fastest.agent_name} "
                f"({fastest.avg_latency_ms:.4f} ms mean). Rule sets differ in size, so "
                "these timings are not like-for-like."
            )

        insights.append(
            "Detection differences reflect which regex families each stand-in implements. "
            "They do not describe how the real products behave."
        )

        return insights
