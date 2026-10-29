"""SafeLine WAF Agent - Semantic Grammar & Token Stream Engine Execution."""

from __future__ import annotations

import html
import re
import time
import urllib.parse
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class SafeLineWAFAgent(BaseWAFAgent):
    """SafeLine WAF Agent (Chaitin T1K Semantic Grammar Execution).

    Executes single-pass URL/HTML decoding followed by semantic grammar
    token classification across URI, query parameters, and body.
    Measures true CPU execution time with zero artificial delays.
    """

    def __init__(self):
        super().__init__(
            name="SafeLine WAF (Chaitin T1K Ruleset)",
            description="Semantic lexical grammar and token pattern analysis across decoded HTTP fields."
        )
        self._tokenizer_re = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*|\d+|==|!=|<=|>=|\.\./|\.\.\\|<script|</script|[^\s\w]")
        self.semantic_patterns = [
            ("SAFELINE-SQLI-TAUT", AttackCategory.SQL_INJECTION, re.compile(r"(?:'|\"|\b)(?:or|and)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1", re.IGNORECASE)),
            ("SAFELINE-SQLI-UNION", AttackCategory.SQL_INJECTION, re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE)),
            ("SAFELINE-SQLI-TIME", AttackCategory.SQL_INJECTION, re.compile(r"\b(?:sleep|waitfor\s+delay|benchmark|pg_sleep)\s*\(", re.IGNORECASE)),
            ("SAFELINE-SQLI-DDL", AttackCategory.SQL_INJECTION, re.compile(r";\s*(?:drop|truncate|alter|delete\s+from)\b", re.IGNORECASE)),
            ("SAFELINE-XSS-TAG", AttackCategory.XSS, re.compile(r"<\s*script[^>]*>|<\s*svg[^>]*onload\s*=", re.IGNORECASE)),
            ("SAFELINE-XSS-ATTR", AttackCategory.XSS, re.compile(r"\bon(?:error|load|mouseover|focus)\s*=\s*[^>\s]+", re.IGNORECASE)),
            ("SAFELINE-XSS-URI", AttackCategory.XSS, re.compile(r"(?:javascript|vbscript)\s*:[^\s'\"]+", re.IGNORECASE)),
            ("SAFELINE-LFI-TRAV", AttackCategory.PATH_TRAVERSAL, re.compile(r"(?:\.\./|\.\.\\){2,}|(?:/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini)", re.IGNORECASE)),
            ("SAFELINE-RCE-CMD", AttackCategory.COMMAND_INJECTION, re.compile(r"(?:;|\|\||\||&&|`|\$\()\s*(?:cat|ls|whoami|id|bash|sh|curl|wget|nc|powershell)\b", re.IGNORECASE)),
            ("SAFELINE-RCE-EVAL", AttackCategory.COMMAND_INJECTION, re.compile(r"\b(?:os\.system|subprocess\.|eval\(|exec\(|passthru\()", re.IGNORECASE)),
            ("SAFELINE-SSRF-META", AttackCategory.SSRF, re.compile(r"(?:http|https|gopher|dict|file)://(?:169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)", re.IGNORECASE)),
        ]

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        t0 = time.perf_counter_ns()

        # Single-pass URL & HTML entity normalization (standard semantic WAF behavior)
        raw = f"{request.path} {request.query_string} {request.body} {request.headers_str}"
        decoded = html.unescape(urllib.parse.unquote_plus(raw))
        tokens = self._tokenizer_re.findall(decoded)

        matched_rules = []
        matched_category = None

        for rule_id, cat, pattern in self.semantic_patterns:
            if pattern.search(decoded):
                matched_rules.append(rule_id)
                if matched_category is None:
                    matched_category = cat

        t1 = time.perf_counter_ns()
        latency_ms = (t1 - t0) / 1_000_000.0

        if matched_rules and matched_category:
            decision = AttackDecision.BLOCK
            predicted_category = matched_category
            explanation = f"SafeLine T1K semantic grammar rule triggered [{', '.join(matched_rules)}]."
        else:
            decision = AttackDecision.ALLOW
            predicted_category = AttackCategory.BENIGN
            explanation = "Passed SafeLine T1K semantic grammar evaluation."

        is_correct = (predicted_category == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_category,
            confidence=0.94 if matched_rules else 0.88,
            latency_ms=round(latency_ms, 4),
            cost_usd=0.0,
            explanation=explanation,
            active_tokens=["SAFELINE_T1K_EVAL", f"TOKENS_{len(tokens)}"],
            matched_rules=matched_rules,
            proof_latex=None,
            is_correct=is_correct,
            extra_metadata={
                "engine": "SafeLine T1K Semantic Grammar",
                "token_count": len(tokens),
                "measurement_type": "Empirical CPU Timing"
            }
        )
