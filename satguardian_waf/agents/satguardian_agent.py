"""SATGuardian Edge WAF Agent - Fast-Path Deterministic Boolean Evaluator."""

from __future__ import annotations

from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision
from satguardian_waf.core.solver_sat import SatguardianWAFSATEngine, ExactorWAFSATEngine


class SatguardianWAFAgent(BaseWAFAgent):
    """SATGuardian Edge WAF Agent.
    
    Uses deterministic AST Token Constraints & Boolean Bitmask Resolution.
    Low false-positive rate, sub-millisecond execution, zero API token cost.
    100% Free & Unlimited Edge Traffic.
    """

    def __init__(self):
        super().__init__(
            name="SATGuardian-Edge (SAT / Neuro-Symbolic)",
            description="Deterministic boolean bitmask engine with structured causal traces and zero external API latency."
        )
        self.engine = SatguardianWAFSATEngine()

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        proof = self.engine.evaluate_payload(request)
        latency_ms = proof.execution_time_us / 1000.0

        decision = AttackDecision.BLOCK if proof.is_violation else AttackDecision.ALLOW
        predicted_category = proof.category if proof.is_violation else AttackCategory.BENIGN

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        explanation = (
            f"Blocked by SAT invariant [{', '.join(r.rule_id for r in proof.matched_rules)}]: {proof.deduction_steps[0]}"
            if proof.is_violation and proof.matched_rules
            else "Clean AST grammar verified. Zero security invariants violated."
        )

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=0.99,
            latency_ms=round(latency_ms, 4),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=proof.active_tokens,
            matched_rules=[r.rule_id for r in proof.matched_rules],
            proof_latex=proof.decision_reason,
            is_correct=is_correct,
            extra_metadata={
                "engine": "SAT-Certainty-Islands-V1",
                "rules_evaluated": len(self.engine.KNOWN_RULES),
                "islands_evaluated": len(self.engine.CERTAINTY_ISLANDS),
                "active_islands": proof.active_islands,
                "rule_match_details": True,
                "token_count": len(proof.active_tokens),
                "measurement_type": "Empirical CPU Timing"
            }
        )


# Backward compatibility alias
ExactorWAFAgent = SatguardianWAFAgent
