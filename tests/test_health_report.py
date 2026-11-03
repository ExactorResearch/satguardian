"""Tests for the local rule-set health report (satguardian-health.py).

The tool is stdlib-only and must not need the cloud, so the tests build their own config and
ledger in a temporary directory instead of reading the demo files in the repository.
"""

import importlib.util
import sqlite3
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("satguardian_health", ROOT / "satguardian-health.py")
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)

CONFIG = """
listen_addr = "127.0.0.1:8080"
database_path = "ignored.db"

[islands]
wordpress_shield = true
exposure_shield = false

[business_rules]
enabled = true

[[business_rules.rules]]
id = "biz-api-methods"
name = "API method list"
path_prefix = "/api/v1/"
allowed_methods = ["GET", "POST", "PUT"]
blocked_methods = ["TRACE"]
enabled = true

[[business_rules.rules]]
id = "biz-products"
name = "Products"
path_prefix = "/api/v1/products"
allowed_methods = ["GET"]
blocked_methods = ["PUT"]
enabled = true

[[business_rules.rules]]
id = "biz-products"
name = "Products copy"
path_prefix = "/api/v1/products"
allowed_methods = ["GET"]
blocked_methods = ["PUT"]
enabled = false
"""


def write_config(tmp_path):
    path = tmp_path / "waf_config.toml"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def build_ledger(tmp_path):
    path = tmp_path / "ledger.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT,
            method TEXT,
            path TEXT,
            query_string TEXT,
            action TEXT,
            category TEXT,
            execution_path TEXT,
            latency_us REAL,
            matched_rules TEXT,
            active_tokens TEXT,
            causal_proof TEXT,
            is_violation INTEGER
        );
        CREATE TABLE novel_anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            minterm_u128 TEXT UNIQUE NOT NULL,
            feature_bits TEXT NOT NULL,
            occurrence_count INTEGER DEFAULT 1,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending'
        );
        CREATE TABLE cloud_simplification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            variables_count INTEGER,
            minterms_count INTEGER,
            reduction_percent REAL,
            original_gates INTEGER,
            new_gates INTEGER,
            execution_time_ms INTEGER,
            su_used INTEGER,
            equation TEXT
        );
        INSERT INTO audit_log (request_id, action, category, path, matched_rules)
            VALUES ('r1', 'Block', 'sql_injection', '/search', 'SAT-SQLI-01'),
                   ('r2', 'Allow', 'benign', '/home', NULL),
                   ('r3', 'Block', 'xss', '/comment', 'SAT-XSS-01');
        INSERT INTO novel_anomalies (minterm_u128, feature_bits) VALUES ('42', '1010');
        INSERT INTO cloud_simplification_history (variables_count, minterms_count, su_used)
            VALUES (12, 50, 5);
        """
    )
    connection.commit()
    connection.close()
    return path


def test_subset_parser_matches_the_stdlib_parser():
    text = CONFIG
    parsed = health._parse_toml_subset(text)
    assert parsed["business_rules"]["enabled"] is True
    assert parsed["database_path"] == "ignored.db"
    assert [rule["id"] for rule in parsed["business_rules"]["rules"]][:2] == [
        "biz-api-methods",
        "biz-products",
    ]
    assert parsed["business_rules"]["rules"][1]["blocked_methods"] == ["PUT"]
    assert parsed["islands"]["exposure_shield"] is False


def test_rules_report_duplicate_ids_and_method_conflicts(tmp_path):
    config = health._parse_toml_subset(CONFIG)
    findings = []
    rules = health.analyse_rules(config, findings)

    assert rules["total"] == 3
    assert rules["enabled"] == 2
    assert rules["islands_enabled"] == ["wordpress_shield"]
    codes = {finding["code"] for finding in findings}
    assert "duplicate_rule_id" in codes
    assert "method_conflict" in codes
    conflict = next(f for f in findings if f["code"] == "method_conflict")
    assert "PUT" in conflict["message"]


def test_ledger_report_is_read_only_and_counts_decisions(tmp_path):
    ledger = build_ledger(tmp_path)
    before = ledger.read_bytes()
    connection = health.open_ledger(str(ledger))
    findings = []
    rules = health.analyse_rules(health._parse_toml_subset(CONFIG), findings)
    traffic = health.analyse_ledger(connection, rules["rules"], findings, 5)
    connection.close()

    assert ledger.read_bytes() == before, "the health report must not write to the ledger"
    assert traffic["total"] == 3
    assert traffic["blocked"] == 2
    assert traffic["allowed"] == 1
    assert traffic["block_rate_pct"] == pytest.approx(66.7)
    assert traffic["novel_anomalies_pending"] == 1
    assert traffic["cloud_compression"]["su_used"] == 5
    assert {item["category"] for item in traffic["top_blocked_categories"]} == {
        "sql_injection",
        "xss",
    }
    assert traffic["business_rules_without_match"] == ["biz-api-methods", "biz-products"]


def test_missing_ledger_is_reported_not_crashed(tmp_path):
    findings = []
    rules = health.analyse_rules(health._parse_toml_subset(CONFIG), findings)
    traffic = health.analyse_ledger(health.open_ledger(str(tmp_path / "absent.db")), rules["rules"], findings, 5)
    assert traffic is None
    assert any(finding["code"] == "ledger_missing" for finding in findings)
