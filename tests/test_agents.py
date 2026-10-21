"""Tests for WAF Agents."""

import pytest
from exactor_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision
from exactor_waf.agents.exactor_agent import ExactorWAFAgent
from exactor_waf.agents.jev_pure_agent import PureJEVAgent
from exactor_waf.agents.regex_baseline_agent import RegexBaselineAgent


def test_exactor_agent_speed_and_decision():
    agent = ExactorWAFAgent()
    req = HTTPRequestPayload(
        method="GET",
        path="/search",
        query_string="id=1' UNION SELECT username,password FROM users--",
        expected_category=AttackCategory.SQL_INJECTION
    )
    decision = agent.inspect(req)
    assert decision.decision == AttackDecision.BLOCK
    assert decision.predicted_category == AttackCategory.SQL_INJECTION
    assert decision.latency_ms < 15.0, f"Exactor SAT agent exceeded latency SLA threshold: {decision.latency_ms} ms"
    assert decision.cost_usd == 0.0
    assert decision.proof_latex is not None


def test_pure_jev_agent():
    agent = PureJEVAgent(simulated_latency_ms=10.0)
    req = HTTPRequestPayload(
        method="GET",
        path="/login",
        query_string="msg=hello",
        expected_category=AttackCategory.BENIGN
    )
    decision = agent.inspect(req)
    assert decision.cost_usd > 0.0
    assert decision.latency_ms >= 5.0


def test_regex_agent():
    agent = RegexBaselineAgent()
    req = HTTPRequestPayload(
        method="GET",
        path="/vuln",
        query_string="test=1 OR 1=1",
        expected_category=AttackCategory.SQL_INJECTION
    )
    decision = agent.inspect(req)
    assert decision.decision == AttackDecision.BLOCK
