"""FastAPI Web Server for SATGuardian Edge WAF Dashboard."""

from __future__ import annotations

import os
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision
from satguardian_waf.core.dataset import get_benchmark_dataset, generate_synthetic_attack_stream
from satguardian_waf.core.solver_sat import SatguardianWAFSATEngine
from satguardian_waf.agents.satguardian_agent import SatguardianWAFAgent
from satguardian_waf.agents.jev_pure_agent import PureJEVAgent
from satguardian_waf.agents.regex_baseline_agent import RegexBaselineAgent
from satguardian_waf.benchmark.runner import WAFBenchmarkRunner

app = FastAPI(
    title="SATGuardian Edge WAF API",
    description="Deterministic SAT Security & Multi-Agent WAF Benchmark Dashboard",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Instantiate Agents
satguardian_agent = SatguardianWAFAgent()
jev_agent = PureJEVAgent()
regex_agent = RegexBaselineAgent()
benchmark_runner = WAFBenchmarkRunner(agents=[satguardian_agent, jev_agent, regex_agent])


class InspectRequest(BaseModel):
    method: str = "GET"
    path: str = "/search"
    query_string: str = "q=test"
    body: str = ""
    headers: Dict[str, str] = {}
    expected_category: Optional[str] = None


class BenchmarkRunRequest(BaseModel):
    num_requests: int = 50
    attack_ratio: float = 0.5
    seed: int = 42


class ContactLeadRequest(BaseModel):
    name: str
    email: str
    company_role: str
    use_case: str


@app.post("/api/contact")
def submit_contact_lead(lead: ContactLeadRequest):
    """Stores inbound enterprise demo / lead inquiries."""
    print(f"[LEAD CAPTURED] Name: {lead.name} | Email: {lead.email} | Role: {lead.company_role} | Volume/Use Case: {lead.use_case}")
    return {
        "status": "success",
        "message": "Demo inquiry registered. The SATGuardian team will reach out at contact@satguardian.tech.",
        "recipient": "contact@satguardian.tech",
        "lead": lead.dict()
    }


@app.get("/api/waf/rules")
def get_rules():
    """Returns the catalog of formal SAT deduction rules."""
    rules = [
        {
            "rule_id": r.rule_id,
            "island_id": r.island_id,
            "category": r.category.value,
            "name": r.name,
            "description": r.description,
            "invariant_formula": r.invariant_formula,
            "confidence": r.confidence,
        }
        for r in SatguardianWAFSATEngine.KNOWN_RULES.values()
    ]
    return {"status": "ok", "count": len(rules), "rules": rules}


@app.get("/api/waf/islands")
def get_islands():
    """Returns the catalog of Certainty Islands."""
    islands = [
        {
            "island_id": isl.island_id,
            "name": isl.name,
            "category": isl.category.value,
            "description": isl.description,
            "formal_invariant": isl.formal_invariant,
            "confidence": isl.confidence,
        }
        for isl in SatguardianWAFSATEngine.CERTAINTY_ISLANDS.values()
    ]
    return {"status": "ok", "count": len(islands), "islands": islands}


@app.get("/api/waf/samples")
def get_samples():
    """Returns the curated benchmark dataset samples."""
    samples = get_benchmark_dataset()
    return {
        "status": "ok",
        "count": len(samples),
        "samples": [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "method": s.method,
                "path": s.path,
                "query_string": s.query_string,
                "body": s.body,
                "headers": s.headers,
                "expected_category": s.expected_category.value,
                "is_obfuscated": s.is_obfuscated,
                "tags": s.tags,
            }
            for s in samples
        ]
    }


@app.post("/api/waf/inspect")
def inspect_payload(req: InspectRequest):
    """Inspects a single payload across SATGuardian, Pure JEV, and Regex."""
    cat = AttackCategory.UNKNOWN
    if req.expected_category:
        try:
            cat = AttackCategory(req.expected_category)
        except ValueError:
            cat = AttackCategory.UNKNOWN

    payload = HTTPRequestPayload(
        method=req.method,
        path=req.path,
        query_string=req.query_string,
        body=req.body,
        headers=req.headers,
        expected_category=cat
    )

    dec_satguardian = satguardian_agent.inspect(payload)
    dec_jev = jev_agent.inspect(payload)
    dec_regex = regex_agent.inspect(payload)

    def serialize_decision(d):
        return {
            "agent_name": d.agent_name,
            "decision": d.decision.value,
            "is_blocked": d.is_blocked,
            "predicted_category": d.predicted_category.value,
            "confidence": d.confidence,
            "latency_ms": d.latency_ms,
            "cost_usd": d.cost_usd,
            "explanation": d.explanation,
            "active_tokens": d.active_tokens,
            "matched_rules": d.matched_rules,
            "proof_latex": d.proof_latex,
            "is_correct": d.is_correct,
            "extra_metadata": d.extra_metadata,
        }

    return {
        "status": "ok",
        "request": {
            "method": payload.method,
            "path": payload.path,
            "query_string": payload.query_string,
            "body": payload.body,
            "expected_category": payload.expected_category.value,
            "is_obfuscated": payload.is_obfuscated,
        },
        "agents": {
            "satguardian": serialize_decision(dec_satguardian),
            "jev_pure": serialize_decision(dec_jev),
            "regex": serialize_decision(dec_regex),
        }
    }


@app.post("/api/waf/benchmark/run")
def run_benchmark_endpoint(req: BenchmarkRunRequest):
    """Runs a multi-agent benchmark on an attack stream."""
    limit_reqs = min(250, max(10, req.num_requests))
    res = benchmark_runner.run_benchmark(num_requests=limit_reqs, attack_ratio=req.attack_ratio, seed=req.seed)

    serialized_metrics = {}
    for name, m in res.agent_metrics.items():
        serialized_metrics[name] = {
            "agent_name": m.agent_name,
            "total_requests": m.total_requests,
            "accuracy": m.accuracy,
            "precision": m.precision,
            "recall": m.recall,
            "f1_score": m.f1_score,
            "false_positive_rate": m.false_positive_rate,
            "false_negative_rate": m.false_negative_rate,
            "avg_latency_ms": m.avg_latency_ms,
            "p50_latency_ms": m.p50_latency_ms,
            "p95_latency_ms": m.p95_latency_ms,
            "p99_latency_ms": m.p99_latency_ms,
            "total_cost_usd": m.total_cost_usd,
            "cost_per_million_usd": m.cost_per_million_usd,
            "throughput_rps": m.throughput_rps,
            "true_positives": m.true_positives,
            "true_negatives": m.true_negatives,
            "false_positives": m.false_positives,
            "false_negatives": m.false_negatives,
        }

    return {
        "status": "ok",
        "dataset_size": res.dataset_size,
        "attack_ratio": res.attack_ratio,
        "metrics": serialized_metrics,
        "summary_insights": res.summary_insights,
    }


# Static files mount
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
