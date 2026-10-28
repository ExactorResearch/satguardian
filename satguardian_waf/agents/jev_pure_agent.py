"""Pure JEV (Solo LLM) WAF Agent Simulation."""

from __future__ import annotations

import time
import random
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class PureJEVAgent(BaseWAFAgent):
    """Pure JEV Agent (Solo LLM Cloud Classifier).
    
    Simulates sending the HTTP request context to a large language model API (e.g., GPT-4o / Claude 3.5).
    Exhibits high latency (300–600ms), API token cost ($0.002/req), and stochastic drift on complex obfuscation.
    """

    def __init__(self, simulated_latency_ms: float = 420.0, token_cost_usd: float = 0.0025):
        super().__init__(
            name="Pure JEV (Solo LLM Classifier)",
            description="Probabilistic cloud LLM evaluation with high latency, token metering cost, and stochastic drift."
        )
        self.simulated_latency_base = simulated_latency_ms
        self.token_cost_usd = token_cost_usd

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        # Simulate realistic neural inference jitter (350ms - 580ms)
        jitter = random.uniform(-45.0, 75.0)
        simulated_latency = max(50.0, self.simulated_latency_base + jitter)
        time.sleep(min(0.08, simulated_latency / 1000.0))  # Smooth UI wait simulation

        # Obfuscation & confusion check for LLM drift
        combined = (request.path + " " + request.query_string + " " + request.body).lower()
        has_double_encoding = "%25" in combined or "%2e%2e" in combined
        has_heavy_obfuscation = len(combined) > 200 and ("/**/" in combined or "||" in combined or "${" in combined)

        # Base accuracy logic
        is_attack = request.expected_category != AttackCategory.BENIGN and request.expected_category != AttackCategory.UNKNOWN
        
        # Stochastic hallucination rate: ~10% on obfuscated or nested payloads
        hallucinate = False
        if has_double_encoding or has_heavy_obfuscation or (not is_attack and ("select" in combined or "script" in combined or "system" in combined)):
            if random.random() < 0.28:
                hallucinate = True

        if hallucinate:
            # Flips decision or confuses category
            if is_attack:
                # False Negative: Misses attack due to obfuscation
                decision = AttackDecision.ALLOW
                predicted_category = AttackCategory.BENIGN
                confidence = round(random.uniform(0.62, 0.79), 2)
                explanation = "LLM evaluated context as safe parameterized payload. (Obfuscation evasion bypass)"
            else:
                # False Positive: Blocks legitimate technical traffic
                decision = AttackDecision.BLOCK
                predicted_category = AttackCategory.SQL_INJECTION
                confidence = round(random.uniform(0.70, 0.88), 2)
                explanation = "LLM flagged keyword tokens as potentially malicious syntax. (False Positive Hallucination)"
        else:
            if is_attack:
                decision = AttackDecision.BLOCK
                predicted_category = request.expected_category
                confidence = round(random.uniform(0.91, 0.98), 2)
                explanation = f"LLM identified semantics matching {request.expected_category.value} exploit pattern."
            else:
                decision = AttackDecision.ALLOW
                predicted_category = AttackCategory.BENIGN
                confidence = round(random.uniform(0.92, 0.99), 2)
                explanation = "LLM parsed request semantics as legitimate user application interaction."

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=confidence,
            latency_ms=round(simulated_latency, 1),
            cost_usd=self.token_cost_usd,
            explanation=explanation,
            active_tokens=["LLM_PROMPT_EMBEDDINGS", "TRANSFORMER_ATTENTION_HEADS"],
            matched_rules=["NEURAL_SEMANTIC_MATCH"],
            proof_latex=None,  # Black-box LLMs cannot produce deterministic mathematical SAT proofs
            is_correct=is_correct,
            extra_metadata={
                "model": "gpt-4o-security-v2 (simulated)",
                "input_tokens": 340 + len(combined) // 4,
                "output_tokens": 48,
                "hallucination_drift": hallucinate
            }
        )
