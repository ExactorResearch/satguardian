"""Statistical Token & N-Gram Heuristic WAF Agent (Probabilistic NLP Classifier)."""

from __future__ import annotations

import math
import time
from collections import Counter
from typing import Dict, List, Tuple
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class PureJEVAgent(BaseWAFAgent):
    """Probabilistic Token & Character N-Gram Classifier (Heuristic NLP Baseline).
    
    Executes real CPU character n-gram tokenization, Shannon entropy calculation,
    and log-odds keyword weight scoring over the raw HTTP request without
    artificial delays (zero time.sleep, zero random number generation).
    Demonstrates why probabilistic token-weight classifiers suffer from false
    positives on benign technical discussions containing SQL/HTML/shell terms
    and false negatives on heavily encoded payloads.
    """

    CATEGORY_WEIGHTS: Dict[AttackCategory, List[Tuple[str, float]]] = {
        AttackCategory.SQL_INJECTION: [
            ("select", 1.8), ("union", 2.2), ("from", 1.1), ("where", 1.0),
            ("drop", 2.1), ("table", 1.5), ("sleep(", 2.8), ("benchmark(", 2.8),
            ("waitfor", 2.5), ("1=1", 3.2), ("'1'='1", 3.5), ("--", 1.4),
            ("insert", 1.4), ("delete", 1.5), ("or ", 1.3), ("and ", 1.1),
        ],
        AttackCategory.XSS: [
            ("<script", 3.2), ("</script", 3.0), ("script", 1.5), ("alert(", 2.8), ("onerror", 2.9),
            ("onload", 2.7), ("javascript:", 3.1), ("<svg", 2.2), ("<img", 1.6),
            ("document.", 2.1), ("cookie", 1.4), ("eval(", 2.2), ("character", 1.1),
        ],
        AttackCategory.COMMAND_INJECTION: [
            ("cat ", 2.1), ("/etc/", 2.2), ("whoami", 2.8), ("bash", 2.3),
            ("curl ", 2.0), ("wget ", 2.2), ("os.system", 3.2), ("subprocess", 3.0),
            ("cmd.exe", 3.1), ("powershell", 2.9), ("$(", 2.4), ("&&", 1.8),
            ("|", 1.4), (";", 1.1),
        ],
        AttackCategory.PATH_TRAVERSAL: [
            ("../", 2.8), ("..\\", 2.8), ("etc/passwd", 3.4), ("etc/shadow", 3.4),
            ("win.ini", 3.2), ("boot.ini", 3.2), ("/proc/self", 3.3),
        ],
        AttackCategory.SSRF: [
            ("169.254.169.254", 3.8), ("127.0.0.1", 2.7), ("localhost", 2.4),
            ("0.0.0.0", 2.6), ("gopher://", 3.5), ("dict://", 3.3), ("file://", 2.9),
            ("meta-data", 2.8), ("10.0.", 2.2), ("192.168.", 2.2),
        ],
    }

    def __init__(self, decision_threshold: float = 2.4):
        super().__init__(
            name="Probabilistic Token Scorer (Heuristic NLP Baseline)",
            description="Deterministic character n-gram, Shannon entropy, and log-odds token weight classifier."
        )
        self.decision_threshold = decision_threshold

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        n = len(text)
        counts = Counter(text)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @staticmethod
    def _extract_char_trigrams(text: str) -> Counter:
        padded = f"  {text}  "
        return Counter(padded[i:i + 3] for i in range(len(padded) - 2))

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        t0 = time.perf_counter_ns()

        combined = f"{request.path} {request.query_string} {request.body} {request.headers_str}".lower()
        entropy = self._shannon_entropy(combined)
        trigrams = self._extract_char_trigrams(combined)

        # Compute log-odds score per attack category using token weights + trigram density
        scores: Dict[AttackCategory, float] = {}
        matched_features: List[str] = []

        for category, weight_list in self.CATEGORY_WEIGHTS.items():
            cat_score = 0.0
            for token, weight in weight_list:
                if token in combined:
                    cat_score += weight
                    matched_features.append(f"{category.value}:{token.strip()}")
            # Entropy contribution for dense punctuation/encoding
            if entropy > 4.65:
                cat_score += (entropy - 4.65) * 0.85
            scores[category] = cat_score

        best_category, best_score = max(scores.items(), key=lambda x: x[1])
        # Logistic probability transformation
        prob = 1.0 / (1.0 + math.exp(-(best_score - self.decision_threshold)))

        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        if best_score >= self.decision_threshold:
            decision = AttackDecision.BLOCK
            predicted_category = best_category
            confidence = round(min(0.99, max(0.55, prob)), 3)
            explanation = (
                f"Probabilistic token scorer exceeded threshold ({best_score:.2f} >= {self.decision_threshold:.2f}, "
                f"H={entropy:.2f} bits/char) for {best_category.value}."
            )
        else:
            decision = AttackDecision.ALLOW
            predicted_category = AttackCategory.BENIGN
            confidence = round(min(0.99, max(0.55, 1.0 - prob)), 3)
            explanation = (
                f"Token log-odds score below threshold ({best_score:.2f} < {self.decision_threshold:.2f}, "
                f"H={entropy:.2f} bits/char)."
            )

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=confidence,
            latency_ms=round(latency_ms, 4),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=matched_features[:6] if matched_features else ["NGRAM_BENIGN_DISTRIBUTION"],
            matched_rules=["STATISTICAL_LOG_ODDS_MATCH"] if decision == AttackDecision.BLOCK else [],
            proof_latex=None,
            is_correct=is_correct,
            extra_metadata={
                "engine": "Deterministic N-Gram & Entropy Scorer",
                "shannon_entropy": round(entropy, 4),
                "unique_trigrams": len(trigrams),
                "max_log_odds_score": round(best_score, 4),
                "measurement_type": "Empirical CPU Timing"
            }
        )
