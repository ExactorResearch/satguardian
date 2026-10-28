"""Regex Baseline Agent - Classical ModSecurity / OWASP CRS Simulation."""

from __future__ import annotations

import re
import time
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class RegexBaselineAgent(BaseWAFAgent):
    """Regex Baseline Agent.
    
    Simulates standard regex-based signatures (e.g., ModSecurity OWASP Core Rule Set).
    Vulnerable to evasion bypasses (comment splitting, alternate encodings) and false positive triggers.
    """

    def __init__(self):
        super().__init__(
            name="Classical Regex (ModSecurity CRS Baseline)",
            description="Traditional regular expression signature matching. Prone to evasion bypasses and false positives."
        )
        self.rules = [
            ("REGEX-SQLI-01", AttackCategory.SQL_INJECTION, re.compile(r"(\bor\b|\band\b)\s+\d+=\d+", re.IGNORECASE)),
            ("REGEX-SQLI-02", AttackCategory.SQL_INJECTION, re.compile(r"\bunion\s+select\b", re.IGNORECASE)),  # missed by comment splitting
            ("REGEX-SQLI-03", AttackCategory.SQL_INJECTION, re.compile(r"\bsleep\(\d+\)", re.IGNORECASE)),
            ("REGEX-XSS-01", AttackCategory.XSS, re.compile(r"<script.*?>", re.IGNORECASE)),
            ("REGEX-XSS-02", AttackCategory.XSS, re.compile(r"javascript:[a-zA-Z0-9_]+", re.IGNORECASE)),
            ("REGEX-RCE-01", AttackCategory.COMMAND_INJECTION, re.compile(r";\s*(cat|ls|whoami|bash|nc)\b", re.IGNORECASE)),
            ("REGEX-PATH-01", AttackCategory.PATH_TRAVERSAL, re.compile(r"\.\./\.\./", re.IGNORECASE)),
            ("REGEX-SSRF-01", AttackCategory.SSRF, re.compile(r"169\.254\.169\.254|127\.0\.0\.1", re.IGNORECASE)),
        ]

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        t0 = time.perf_counter()

        combined = f"{request.path} {request.query_string} {request.body} {request.headers_str}"
        matched_rule_id = None
        matched_category = None

        # ReDoS simulation on long backtracking inputs
        if len(combined) > 300:
            time.sleep(0.001)

        for rule_id, cat, pattern in self.rules:
            if pattern.search(combined):
                matched_rule_id = rule_id
                matched_category = cat
                break

        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0

        if matched_rule_id:
            decision = AttackDecision.BLOCK
            predicted_category = matched_category
            explanation = f"Matched signature rule [{matched_rule_id}]."
        else:
            decision = AttackDecision.ALLOW
            predicted_category = AttackCategory.BENIGN
            explanation = "No signature patterns matched in request stream."

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=0.85 if matched_rule_id else 0.70,
            latency_ms=round(latency_ms, 3),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=["REGEX_BYTE_SCAN"],
            matched_rules=[matched_rule_id] if matched_rule_id else [],
            proof_latex=None,
            is_correct=is_correct,
            extra_metadata={
                "signatures_tested": len(self.rules),
                "encoding_aware": False
            }
        )
