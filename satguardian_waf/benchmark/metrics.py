"""Performance and Accuracy Metrics for WAF Evaluation."""

from __future__ import annotations

import numpy as np
from typing import List, Dict, Any
from dataclasses import dataclass, field
from satguardian_waf.agents.base import WAFAgentDecision
from satguardian_waf.core.payload import AttackCategory, AttackDecision


@dataclass
class AgentBenchmarkMetrics:
    """Consolidated benchmark metrics for a single WAF agent."""
    agent_name: str
    total_requests: int
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    
    total_cost_usd: float = 0.0
    cost_per_million_usd: float = 0.0
    throughput_rps: float = 0.0
    
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0

    decisions: List[WAFAgentDecision] = field(default_factory=list)


def compute_metrics(agent_name: str, decisions: List[WAFAgentDecision], ground_truth: List[AttackCategory]) -> AgentBenchmarkMetrics:
    """Computes full precision, recall, latency quantiles and financial costs for WAF decisions."""
    total = len(decisions)
    if total == 0:
        return AgentBenchmarkMetrics(agent_name=agent_name, total_requests=0)

    tp, tn, fp, fn = 0, 0, 0, 0
    latencies = []
    total_cost = 0.0

    for dec, gt in zip(decisions, ground_truth):
        latencies.append(dec.latency_ms)
        total_cost += dec.cost_usd

        is_actual_attack = (gt != AttackCategory.BENIGN and gt != AttackCategory.UNKNOWN)
        is_pred_block = (dec.decision == AttackDecision.BLOCK)

        if is_actual_attack and is_pred_block:
            tp += 1
        elif not is_actual_attack and not is_pred_block:
            tn += 1
        elif not is_actual_attack and is_pred_block:
            fp += 1
        elif is_actual_attack and not is_pred_block:
            fn += 1

    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    lat_arr = np.array(latencies)
    avg_lat = float(np.mean(lat_arr))
    p50_lat = float(np.percentile(lat_arr, 50))
    p95_lat = float(np.percentile(lat_arr, 95))
    p99_lat = float(np.percentile(lat_arr, 99))

    throughput_rps = 1000.0 / avg_lat if avg_lat > 0 else 50000.0
    cost_per_m = (total_cost / total) * 1_000_000 if total > 0 else 0.0

    return AgentBenchmarkMetrics(
        agent_name=agent_name,
        total_requests=total,
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn,
        avg_latency_ms=round(avg_lat, 3),
        p50_latency_ms=round(p50_lat, 3),
        p95_latency_ms=round(p95_lat, 3),
        p99_latency_ms=round(p99_lat, 3),
        total_cost_usd=round(total_cost, 4),
        cost_per_million_usd=round(cost_per_m, 2),
        throughput_rps=round(throughput_rps, 1),
        accuracy=round(accuracy, 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        false_positive_rate=round(fpr, 4),
        false_negative_rate=round(fnr, 4),
        decisions=decisions
    )
