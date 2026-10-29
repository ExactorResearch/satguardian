"""Docker HTTP WAF Connector Agent - Connects to live Docker containers running competitor WAFs."""

from __future__ import annotations

import time
import urllib.request
import urllib.parse
import urllib.error
from satguardian_waf.agents.base import BaseWAFAgent, WAFAgentDecision
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


class DockerHTTPWAFAgent(BaseWAFAgent):
    """Generic Connector Agent for live HTTP / Docker WAF endpoints.

    Sends real HTTP requests over local socket or TCP endpoint to live Docker containers
    running competitor WAFs (e.g., ModSecurity Nginx container on port 8081, Coraza on port 8082, SafeLine on port 8083)
    and measures actual HTTP status codes (200 vs 403) and round-trip latency.
    """

    def __init__(self, name: str, endpoint_url: str, timeout_sec: float = 2.0):
        super().__init__(
            name=name,
            description=f"Live Docker HTTP WAF endpoint connector at {endpoint_url}"
        )
        self.endpoint_url = endpoint_url.rstrip("/")
        self.timeout_sec = timeout_sec

    def inspect(self, request: HTTPRequestPayload) -> WAFAgentDecision:
        url = f"{self.endpoint_url}{request.path}"
        if request.query_string:
            url += f"?{request.query_string}"

        req_headers = {"User-Agent": "SATGuardian-Benchmark-Client/1.0"}
        if request.headers:
            req_headers.update(request.headers)

        data = request.body.encode("utf-8") if request.body else None
        method = request.method if request.method else ("POST" if data else "GET")

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)

        t0 = time.perf_counter()
        blocked = False
        status_code = 200

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                status_code = resp.status
                if status_code in (403, 406, 429, 502):
                    blocked = True
        except urllib.error.HTTPError as e:
            status_code = e.code
            if e.code in (403, 406, 429, 502):
                blocked = True
        except Exception:
            # Endpoint unreachable or connection refused -> fallback
            blocked = False
            status_code = 0

        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0

        decision = AttackDecision.BLOCK if blocked else AttackDecision.ALLOW
        predicted_cat = request.expected_category if blocked else AttackCategory.BENIGN

        is_correct = (predicted_cat == request.expected_category) if request.expected_category != AttackCategory.UNKNOWN else None

        return WAFAgentDecision(
            agent_name=self.name,
            decision=decision,
            predicted_category=predicted_cat,
            confidence=0.95 if blocked else 0.85,
            latency_ms=round(latency_ms, 3),
            cost_usd=0.0,
            explanation=f"Live HTTP response code [{status_code}] from {self.endpoint_url}",
            active_tokens=["DOCKER_HTTP_INTERCEPT"],
            matched_rules=[f"HTTP-{status_code}"] if blocked else [],
            proof_latex=None,
            is_correct=is_correct,
            extra_metadata={
                "live_endpoint": self.endpoint_url,
                "http_status": status_code
            }
        )

