"""Tests for HTTPRequestPayload data structure."""

import pytest
from satguardian_waf.core.payload import HTTPRequestPayload, AttackCategory, AttackDecision


def test_payload_normalization():
    req = HTTPRequestPayload(
        method="GET",
        path="/api/search",
        query_string="id=1%20UNION%20SELECT%201,2",
        expected_category=AttackCategory.SQL_INJECTION
    )
    assert req.is_obfuscated is True
    assert "UNION SELECT" in req.normalized_text
    assert req.method == "GET"


def test_benign_payload():
    req = HTTPRequestPayload(
        method="POST",
        path="/api/v1/checkout",
        body='{"item_id": 42, "quantity": 1}',
        expected_category=AttackCategory.BENIGN
    )
    assert req.is_obfuscated is False
    assert req.expected_category == AttackCategory.BENIGN
