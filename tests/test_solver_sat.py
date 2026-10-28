"""Tests for SATGuardian Edge WAF SAT Engine."""

import pytest
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory
from satguardian_waf.core.solver_sat import SatguardianWAFSATEngine, ExactorWAFSATEngine


@pytest.fixture
def sat_engine():
    return SatguardianWAFSATEngine()


def test_sqli_detection(sat_engine):
    req = HTTPRequestPayload(
        method="GET",
        path="/items",
        query_string="id=1' OR '1'='1",
        expected_category=AttackCategory.SQL_INJECTION
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is True
    assert proof.category == AttackCategory.SQL_INJECTION
    assert len(proof.matched_rules) > 0
    assert "SAT-SQLI-01" in proof.formal_proof_latex


def test_xss_detection(sat_engine):
    req = HTTPRequestPayload(
        method="GET",
        path="/comment",
        query_string="msg=<script>alert(1)</script>",
        expected_category=AttackCategory.XSS
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is True
    assert proof.category == AttackCategory.XSS
    assert "SAT-XSS-01" in [r.rule_id for r in proof.matched_rules]


def test_rce_detection(sat_engine):
    req = HTTPRequestPayload(
        method="POST",
        path="/api/ping",
        body='ip=127.0.0.1; cat /etc/passwd',
        expected_category=AttackCategory.COMMAND_INJECTION
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is True
    assert proof.category == AttackCategory.COMMAND_INJECTION
    assert "SAT-RCE-01" in [r.rule_id for r in proof.matched_rules]


def test_path_traversal_detection(sat_engine):
    req = HTTPRequestPayload(
        method="GET",
        path="/download",
        query_string="file=../../../../etc/passwd",
        expected_category=AttackCategory.PATH_TRAVERSAL
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is True
    assert proof.category == AttackCategory.PATH_TRAVERSAL


def test_ssrf_detection(sat_engine):
    req = HTTPRequestPayload(
        method="GET",
        path="/proxy",
        query_string="url=http://169.254.169.254/latest/meta-data/",
        expected_category=AttackCategory.SSRF
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is True
    assert proof.category == AttackCategory.SSRF


def test_benign_traffic_passes(sat_engine):
    req = HTTPRequestPayload(
        method="POST",
        path="/api/v1/users",
        body='{"username": "alice", "role": "developer"}',
        expected_category=AttackCategory.BENIGN
    )
    proof = sat_engine.evaluate_payload(req)
    assert proof.is_violation is False
    assert proof.category == AttackCategory.BENIGN
    assert len(proof.matched_rules) == 0
    assert "ALLOW" in proof.formal_proof_latex
