"""Regex Baseline Agent - Classical ModSecurity CRS v3 Signature Execution."""

from __future__ import annotations

import re
import time
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class RegexBaselineAgent(BaseWAFAgent):
    """Regex Baseline Agent (Classical ModSecurity CRS Signature Scanning).
    
    Executes traditional regular expression signatures over raw HTTP fields
    without deep multi-pass AST normalization.
    Measures true CPU execution time with zero artificial delays.
    """

    def __init__(self):
        super().__init__(
            name="Classical Regex (ModSecurity CRS Baseline)",
            description="Traditional unnormalized regular expression signature matching."
        )
        self.rules = [
            ("REGEX-SQLI-01", AttackCategory.SQL_INJECTION, re.compile(r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.IGNORECASE)),
            ("REGEX-SQLI-02", AttackCategory.SQL_INJECTION, re.compile(r"\bunion\s+select\b", re.IGNORECASE)),
            ("REGEX-SQLI-03", AttackCategory.SQL_INJECTION, re.compile(r"\bsleep\(\d+\)|\bwaitfor\s+delay\b", re.IGNORECASE)),
            ("REGEX-SQLI-04", AttackCategory.SQL_INJECTION, re.compile(r";\s*drop\s+table\b", re.IGNORECASE)),
            ("REGEX-XSS-01", AttackCategory.XSS, re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE)),
            ("REGEX-XSS-02", AttackCategory.XSS, re.compile(r"javascript:[a-zA-Z0-9_]+|onerror\s*=", re.IGNORECASE)),
            ("REGEX-RCE-01", AttackCategory.COMMAND_INJECTION, re.compile(r"(?:;|\|)\s*(?:cat|ls|whoami|bash|nc|id)\b", re.IGNORECASE)),
            ("REGEX-RCE-02", AttackCategory.COMMAND_INJECTION, re.compile(r"\b(?:os\.system|eval\(|exec\()", re.IGNORECASE)),
            ("REGEX-PATH-01", AttackCategory.PATH_TRAVERSAL, re.compile(r"(?:\.\./){2,}|/etc/passwd|win\.ini", re.IGNORECASE)),
            ("REGEX-SSRF-01", AttackCategory.SSRF, re.compile(r"169\.254\.169\.254|127\.0\.0\.1|localhost", re.IGNORECASE)),
        ]

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        t0 = time.perf_counter_ns()
        targets = [request.path, request.query_string, request.body, request.headers_str]

        matched_rules = []
        matched_category = None

        for target in targets:
            if not target:
                continue
            for rule_id, cat, pattern in self.rules:
                if pattern.search(target):
                    if rule_id not in matched_rules:
                        matched_rules.append(rule_id)
                    if matched_category is None:
                        matched_category = cat

        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        if matched_rules and matched_category:
            decision = AttackDecision.BLOCK
            predicted_category = matched_category
            explanation = f"Matched regex signature rule [{', '.join(matched_rules)}]."
        else:
            decision = AttackDecision.ALLOW
            predicted_category = AttackCategory.BENIGN
            explanation = "No regex signature patterns matched in raw request stream."

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=0.85 if matched_rules else 0.70,
            latency_ms=round(latency_ms, 4),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=["REGEX_BYTE_SCAN"],
            matched_rules=matched_rules,
            proof_latex=None,
            is_correct=is_correct,
            extra_metadata={
                "signatures_tested": len(self.rules) * len(targets),
                "measurement_type": "Empirical CPU Timing"
            }
        )
