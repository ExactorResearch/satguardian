#!/usr/bin/env python3
"""
SATGuardian Rule-Set Health Report — local, read-only, no cloud.

The free Edge binary protects unlimited traffic on its own. This tool answers the question a
free user still has: *is the rule set I wrote doing what I think it does?* It reads the same
`waf_config.toml` and `waf_ledger.db` the proxy uses, and reports:

  * inventory: business rules and certainty islands, enabled vs disabled;
  * structural findings: duplicate ids, rules that allow and block the same method, duplicate
    rule bodies, and overlapping path prefixes whose method lists contradict each other;
  * observed traffic: decisions, block rate, blocked paths/categories, the client IPs that
    generated the most traffic, business rules that have not matched anything in this ledger,
    novel-anomaly candidates waiting for review, and sensitive-looking paths the WAF allowed
    (a prompt to check what the upstream answered, not proof of exposure);
  * cloud compression history recorded in the local ledger, if any.

It never opens a network socket and never uploads anything. The cloud service is not called, no
traffic or rule content leaves the machine, and there is no telemetry. Reading is enforced with
SQLite's `mode=ro` URI and the file is not opened for writing.

Usage
    satguardian-health
    satguardian-health --config /etc/satguardian/waf_config.toml --db /var/lib/satguardian/waf_ledger.db
    satguardian-health --json
    satguardian-health --strict        # exit 1 when a WARN finding is present

Exit codes: 0 = report written, 1 = --strict and at least one WARN, 2 = input error.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict

try:
    import tomllib
except ImportError:  # Python < 3.11
    try:
        import tomli as tomllib  # optional backport
    except ImportError:
        tomllib = None

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_NUMBER = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")


def _strip_comment(text):
    """Remove a trailing # comment without touching # characters inside strings."""
    out = []
    quote = None
    escaped = False
    for char in text:
        if escaped:
            out.append(char)
            escaped = False
            continue
        if quote:
            out.append(char)
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            out.append(char)
            continue
        if char == "#":
            break
        out.append(char)
    return "".join(out).strip()


def _split_top_level(text, separator=","):
    parts = []
    current = []
    quote = None
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if quote:
            current.append(char)
            if char == "\\" and quote == '"':
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            continue
        if char == separator:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def _parse_toml_value(text):
    text = text.strip()
    if not text:
        raise ValueError("empty value")
    if text.startswith('"'):
        return json.loads(text)
    if text.startswith("'"):
        if len(text) < 2 or not text.endswith("'"):
            raise ValueError(f"unterminated string: {text}")
        return text[1:-1]
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError(f"unterminated array: {text}")
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [
            _parse_toml_value(part)
            for part in _split_top_level(inner)
            if part.strip()
        ]
    lowered = text.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if _NUMBER.match(text):
        return float(text) if any(char in text for char in ".eE") else int(text)
    raise ValueError(f"unsupported TOML value: {text}")


def _parse_toml_subset(text):
    """Cover the shapes waf_config.toml uses: key = value, [table], [[array of tables]].

    Only a fallback for Python < 3.11. It refuses what it does not understand instead of
    guessing, so a config it cannot read is reported as an error and not silently analysed.
    """
    root = {}
    current = root
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw_line)
        if not line:
            continue
        try:
            if line.startswith("[[") and line.endswith("]]"):
                path = [part.strip() for part in line[2:-2].split(".")]
                node = root
                for part in path[:-1]:
                    node = node.setdefault(part, {})
                    if not isinstance(node, dict):
                        raise ValueError(f"{part} is not a table")
                entries = node.setdefault(path[-1], [])
                if not isinstance(entries, list):
                    raise ValueError(f"{path[-1]} is not an array of tables")
                entry = {}
                entries.append(entry)
                current = entry
            elif line.startswith("[") and line.endswith("]"):
                path = [part.strip() for part in line[1:-1].split(".")]
                node = root
                for part in path:
                    node = node.setdefault(part, {})
                    if not isinstance(node, dict):
                        raise ValueError(f"{part} is not a table")
                current = node
            else:
                key, separator, value = line.partition("=")
                if not separator:
                    raise ValueError("expected key = value")
                key = key.strip()
                if key.startswith('"') and key.endswith('"'):
                    key = json.loads(key)
                elif not _BARE_KEY.match(key):
                    raise ValueError(f"unsupported key: {key}")
                current[key] = _parse_toml_value(value)
        except ValueError as error:
            raise ValueError(f"line {line_number}: {error}") from error
    return root


def load_config(path):
    with open(path, "rb") as handle:
        if tomllib is not None:
            return tomllib.load(handle)
        return _parse_toml_subset(handle.read().decode("utf-8", errors="replace"))


DEFAULT_CONFIG_PATHS = [
    "/etc/satguardian/waf_config.toml",
    "waf_config.toml",
    "../waf_config.toml",
]
DEFAULT_DB_PATHS = [
    "/var/lib/satguardian/waf_ledger.db",
    "/etc/satguardian/waf_ledger.db",
    "waf_ledger.db",
    "../waf_ledger.db",
]


def first_existing(paths):
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


def norm_list(values):
    return sorted({str(v).strip().upper() for v in (values or []) if str(v).strip()})


def rule_signature(rule):
    return (
        str(rule.get("path_prefix", "") or ""),
        tuple(norm_list(rule.get("allowed_methods"))),
        tuple(norm_list(rule.get("blocked_methods"))),
        tuple(norm_list(rule.get("allowed_ips"))),
        tuple(norm_list(rule.get("blocked_ips"))),
        tuple(norm_list(rule.get("required_headers"))),
        rule.get("max_body_bytes"),
    )


def prefixes_overlap(a, b):
    """A prefix governs a path when the path starts with it; "" governs everything."""
    if not a or not b:
        return True
    return a.startswith(b) or b.startswith(a)


def add(findings, severity, code, message):
    findings.append({"severity": severity, "code": code, "message": message})


# Substrings credential-harvesting scanners probe for. Matching is deliberately conservative
# about *path shape*: it flags requests whose path looks like an exposed secret or installer,
# regardless of which rule (if any) evaluated them. It says nothing about whether the upstream
# actually served the file — that check belongs to the operator.
SENSITIVE_PATH_MARKERS = (
    "/.env",
    "wp-config.php",
    "wp-admin/install.php",
    "wp-content/debug.log",
    "phpinfo.php",
    "info.php",
    "settings.php",
    "settings.json",
    "secrets.json",
    "sendgrid.env",
    "sentry.properties",
    "runtime-config.js",
    "vendor/composer/installed.json",
    "/server-status",
    "/server-info",
    "/elmah.axd",
    "/.git/",
    "/.svn/",
    "/.ssh/",
    "/.aws/credentials",
    "id_rsa",
    "config.yml",
    "config.yaml",
    "database.yml",
    "credentials",
)


def is_sensitive_path(path):
    if not path:
        return False
    lowered = str(path).lower()
    return any(marker in lowered for marker in SENSITIVE_PATH_MARKERS)


def analyse_rules(config, findings):
    section = config.get("business_rules") or {}
    globally_enabled = bool(section.get("enabled", True))
    raw_rules = section.get("rules") or []
    if not isinstance(raw_rules, list):
        raw_rules = []

    rules = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            continue
        rule = {
            "index": index,
            "id": str(raw.get("id") or f"rule[{index}]"),
            "name": str(raw.get("name") or ""),
            "path_prefix": str(raw.get("path_prefix", "") or ""),
            "allowed_methods": norm_list(raw.get("allowed_methods")),
            "blocked_methods": norm_list(raw.get("blocked_methods")),
            "allowed_ips": norm_list(raw.get("allowed_ips")),
            "blocked_ips": norm_list(raw.get("blocked_ips")),
            "required_headers": norm_list(raw.get("required_headers")),
            "max_body_bytes": raw.get("max_body_bytes"),
            "enabled": bool(raw.get("enabled", True)) and globally_enabled,
            "enabled_in_file": bool(raw.get("enabled", True)),
        }
        rules.append(rule)

        both = set(rule["allowed_methods"]) & set(rule["blocked_methods"])
        if both:
            add(
                findings,
                "warn",
                "rule_self_contradiction",
                f"{rule['id']} lists {', '.join(sorted(both))} as both allowed and blocked; "
                "which clause wins depends on evaluation order.",
            )
        if not rule["enabled_in_file"]:
            add(findings, "info", "rule_disabled", f"{rule['id']} is disabled and not evaluated.")
        if not rule["path_prefix"]:
            add(
                findings,
                "info",
                "rule_global_scope",
                f"{rule['id']} has an empty path_prefix, so it applies to every path.",
            )

    if not globally_enabled:
        add(
            findings,
            "info",
            "business_rules_disabled",
            "business_rules.enabled is false: no customer rule below is evaluated.",
        )

    ids = Counter(rule["id"] for rule in rules)
    for rule_id, count in ids.items():
        if count > 1:
            add(
                findings,
                "warn",
                "duplicate_rule_id",
                f"id {rule_id} is used by {count} rules; matched_rules in the ledger cannot tell them apart.",
            )

    enabled_rules = [rule for rule in rules if rule["enabled"]]

    groups = defaultdict(list)
    for rule in enabled_rules:
        groups[rule_signature(rule)].append(rule)
    for members in groups.values():
        if len(members) > 1:
            add(
                findings,
                "warn",
                "duplicate_rule_body",
                "these enabled rules have the same prefix, methods, IPs, headers and body limit: "
                + ", ".join(rule["id"] for rule in members),
            )

    exact_duplicate_ids = {
        tuple(sorted(rule["id"] for rule in members))
        for members in groups.values()
        if len(members) > 1
    }

    for i, left in enumerate(enabled_rules):
        for right in enabled_rules[i + 1:]:
            if not prefixes_overlap(left["path_prefix"], right["path_prefix"]):
                continue
            if tuple(sorted([left["id"], right["id"]])) in exact_duplicate_ids:
                continue
            conflicts = set(left["allowed_methods"]) & set(right["blocked_methods"])
            conflicts |= set(right["allowed_methods"]) & set(left["blocked_methods"])
            if conflicts:
                add(
                    findings,
                    "warn",
                    "method_conflict",
                    f"{left['id']} ({left['path_prefix'] or '/'}) and "
                    f"{right['id']} ({right['path_prefix'] or '/'}) disagree on "
                    f"{', '.join(sorted(conflicts))}: one allows it, the other blocks it.",
                )

    islands = config.get("islands") or {}
    islands_enabled = sorted(name for name, value in islands.items() if bool(value))
    islands_disabled = sorted(name for name, value in islands.items() if not bool(value))

    return {
        "business_rules_enabled": globally_enabled,
        "total": len(rules),
        "enabled": len(enabled_rules),
        "disabled": len(rules) - len(enabled_rules),
        "rules": rules,
        "islands_enabled": islands_enabled,
        "islands_disabled": islands_disabled,
    }


def open_ledger(path):
    if not path or not os.path.exists(path):
        return None
    # mode=ro guarantees this report cannot change the proxy's ledger.
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        return connection
    except sqlite3.Error:
        return None


def table_exists(connection, name):
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def analyse_ledger(connection, rules, findings, top_limit):
    if connection is None:
        add(
            findings,
            "info",
            "ledger_missing",
            "No readable ledger was found, so nothing below is based on observed traffic. "
            "Start the proxy once with database_path set, then run this report again.",
        )
        return None

    if not table_exists(connection, "audit_log"):
        add(
            findings,
            "info",
            "ledger_no_audit_log",
            "The ledger has no audit_log table yet: the proxy has not written a decision.",
        )
        return None

    total = connection.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    actions = dict(
        connection.execute(
            "SELECT LOWER(COALESCE(action, 'unknown')), COUNT(*) FROM audit_log GROUP BY 1"
        ).fetchall()
    )
    blocked = actions.get("block", 0)
    allowed = actions.get("allow", 0)
    first, last = connection.execute(
        "SELECT MIN(timestamp), MAX(timestamp) FROM audit_log"
    ).fetchone()

    blocked_paths = connection.execute(
        "SELECT COALESCE(path, '(none)'), COUNT(*) FROM audit_log "
        "WHERE LOWER(COALESCE(action, '')) = 'block' GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
        (top_limit,),
    ).fetchall()

    categories = connection.execute(
        "SELECT COALESCE(category, '(none)'), COUNT(*) FROM audit_log "
        "WHERE LOWER(COALESCE(action, '')) = 'block' GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
        (top_limit,),
    ).fetchall()

    offenders = connection.execute(
        "SELECT COALESCE(NULLIF(client_ip, ''), '(unknown)'), COUNT(*), "
        "SUM(CASE WHEN LOWER(COALESCE(action, '')) = 'block' THEN 1 ELSE 0 END) "
        "FROM audit_log GROUP BY 1 ORDER BY 2 DESC LIMIT ?",
        (top_limit,),
    ).fetchall()

    sensitive = defaultdict(lambda: {"count": 0, "ips": set()})
    for path, client_ip in connection.execute(
        "SELECT COALESCE(path, '(none)'), COALESCE(NULLIF(client_ip, ''), '(unknown)') "
        "FROM audit_log WHERE LOWER(COALESCE(action, '')) = 'allow'"
    ):
        if not is_sensitive_path(path):
            continue
        entry = sensitive[path]
        entry["count"] += 1
        entry["ips"].add(client_ip)
    sensitive_paths = [
        {"path": path, "count": value["count"], "ips": sorted(value["ips"])}
        for path, value in sorted(sensitive.items(), key=lambda kv: (-kv[1]["count"], kv[0]))
    ][:top_limit]
    if sensitive_paths:
        shown = ", ".join(f"{item['path']} ({item['count']})" for item in sensitive_paths[:5])
        total_sensitive = sum(value["count"] for value in sensitive.values())
        add(
            findings,
            "warn",
            "sensitive_paths_allowed",
            f"{total_sensitive} allowed request(s) hit sensitive-looking paths that no rule "
            f"blocked: {shown}. 'Allowed' only means the WAF passed them on; check what the "
            "upstream answered (404 vs 200) and whether these probes should be blocked.",
        )

    matched = set()
    for (value,) in connection.execute(
        "SELECT matched_rules FROM audit_log WHERE matched_rules IS NOT NULL AND matched_rules != ''"
    ):
        for token in str(value).split(","):
            token = token.strip()
            if token:
                matched.add(token)

    enabled_ids = [rule["id"] for rule in rules if rule["enabled"]]
    unmatched = [rule_id for rule_id in enabled_ids if rule_id not in matched]
    if unmatched and total:
        add(
            findings,
            "info",
            "business_rules_never_matched",
            f"{len(unmatched)} enabled business rule(s) have no recorded match in {total} "
            f"decisions: {', '.join(unmatched)}. This ledger may predate the rule or simply not "
            "contain a request it governs; it is a prompt to check, not a defect.",
        )

    novel_pending = None
    if table_exists(connection, "novel_anomalies"):
        novel_pending = connection.execute(
            "SELECT COUNT(*) FROM novel_anomalies WHERE LOWER(COALESCE(status, '')) IN "
            "('pending', 'new', '')"
        ).fetchone()[0]
        if novel_pending:
            add(
                findings,
                "info",
                "novel_anomalies_pending",
                f"{novel_pending} novel-anomaly candidate(s) are waiting for review. "
                "Review them locally; nothing is sent to the cloud by this report.",
            )

    cloud = None
    if table_exists(connection, "cloud_simplification_history"):
        cloud_row = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(su_used), 0), MAX(timestamp) "
            "FROM cloud_simplification_history"
        ).fetchone()
        cloud = {
            "jobs": cloud_row[0],
            "su_used": cloud_row[1],
            "last_job": cloud_row[2],
        }

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "other": total - blocked - allowed,
        "block_rate_pct": round((blocked * 100.0 / total), 1) if total else 0.0,
        "first_seen": first,
        "last_seen": last,
        "top_blocked_paths": [{"path": path, "count": count} for path, count in blocked_paths],
        "top_blocked_categories": [
            {"category": category, "count": count} for category, count in categories
        ],
        "top_offenders": [
            {
                "ip": ip,
                "requests": requests,
                "blocked": blocked_count,
                "blocked_pct": round(blocked_count * 100.0 / requests, 1) if requests else 0.0,
            }
            for ip, requests, blocked_count in offenders
        ],
        "sensitive_paths_allowed": sensitive_paths,
        "business_rules_matched": sorted(set(enabled_ids) & matched),
        "business_rules_without_match": unmatched,
        "novel_anomalies_pending": novel_pending,
        "cloud_compression": cloud,
    }


def print_report(config_path, db_path, rules, traffic, findings):
    print("SATGuardian rule-set health — local, read-only, no cloud call")
    print(f"  Config : {config_path}")
    print(f"  Ledger : {db_path or '(not found)'}")
    print("  Nothing is uploaded. No telemetry. The cloud service is not contacted.")
    print()

    print("Rules")
    state = "enabled" if rules["business_rules_enabled"] else "DISABLED"
    print(f"  Business rules: {rules['total']} ({rules['enabled']} enabled, {rules['disabled']} disabled; section {state})")
    print(f"  Islands enabled: {', '.join(rules['islands_enabled']) or '(none)'}")
    if rules["islands_disabled"]:
        print(f"  Islands disabled: {', '.join(rules['islands_disabled'])}")
    for rule in rules["rules"]:
        flag = "on " if rule["enabled"] else "off"
        methods = ",".join(rule["allowed_methods"]) or "-"
        blocked = ",".join(rule["blocked_methods"]) or "-"
        print(
            f"    [{flag}] {rule['id']:<32} prefix={rule['path_prefix'] or '/'} "
            f"allow={methods} block={blocked}"
        )
    print()

    print("Findings")
    if not findings:
        print("  No structural findings. A clean report is not a guarantee of coverage.")
    else:
        for finding in findings:
            print(f"  [{finding['severity'].upper():<4}] {finding['message']}")
    print()

    if traffic is None:
        print("Traffic")
        print("  No ledger data to report.")
        print()
        return

    print("Traffic (from this ledger only)")
    print(
        f"  Decisions: {traffic['total']:,} ({traffic['blocked']:,} blocked, "
        f"{traffic['allowed']:,} allowed)"
    )
    print(f"  Block rate: {traffic['block_rate_pct']}%")
    print(f"  Window: {traffic['first_seen']} -> {traffic['last_seen']}")
    if traffic["top_blocked_categories"]:
        summary = ", ".join(
            f"{item['category']} {item['count']:,}" for item in traffic["top_blocked_categories"]
        )
        print(f"  Top blocked categories: {summary}")
    if traffic["top_blocked_paths"]:
        summary = ", ".join(
            f"{item['path']} {item['count']:,}" for item in traffic["top_blocked_paths"]
        )
        print(f"  Top blocked paths: {summary}")
    if traffic["top_offenders"]:
        print("  Top offenders (client IPs, most requests first)")
        for item in traffic["top_offenders"]:
            print(
                f"    {item['ip']:<16} {item['requests']:,} requests "
                f"({item['blocked']:,} blocked, {item['blocked_pct']}%)"
            )
    if traffic["sensitive_paths_allowed"]:
        print("  Sensitive paths allowed (verify what the upstream answered)")
        for item in traffic["sensitive_paths_allowed"]:
            ips = ", ".join(item["ips"][:3]) + (" …" if len(item["ips"]) > 3 else "")
            print(f"    {item['path']} — {item['count']:,} request(s) from {ips}")
    if traffic["novel_anomalies_pending"] is not None:
        print(f"  Novel anomalies pending: {traffic['novel_anomalies_pending']}")
    cloud = traffic["cloud_compression"]
    if cloud:
        print(
            f"  Cloud compression history: {cloud['jobs']} job(s), "
            f"{cloud['su_used']} SU recorded, last {cloud['last_job'] or 'never'}"
        )
    else:
        print("  Cloud compression history: none recorded in this ledger")
    print()
    print("Caveat: a rule that never matched in this ledger is a prompt to check it, not proof")
    print("that it is dead; the sample may not contain a request it governs.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Local, read-only SATGuardian rule-set health report (no cloud, no telemetry)."
    )
    parser.add_argument("--config", help="Path to waf_config.toml")
    parser.add_argument("--db", help="Path to waf_ledger.db")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument(
        "--strict", action="store_true", help="Exit 1 when at least one WARN finding is present"
    )
    parser.add_argument("--top", type=int, default=5, help="Rows per top list (default 5)")
    args = parser.parse_args(argv)

    if tomllib is None:
        print("  Note: Python < 3.11 has no tomllib; using the built-in subset parser.", file=sys.stderr)

    config_path = args.config or first_existing(DEFAULT_CONFIG_PATHS)
    if not config_path or not os.path.exists(config_path):
        print(
            "Error: waf_config.toml not found. Pass --config, or run from the directory that "
            "contains it.",
            file=sys.stderr,
        )
        return 2

    try:
        config = load_config(config_path)
    except (OSError, ValueError) as error:
        print(f"Error: could not read {config_path}: {error}", file=sys.stderr)
        return 2

    db_path = args.db
    if not db_path:
        configured = config.get("database_path")
        candidates = ([configured] if configured else []) + DEFAULT_DB_PATHS
        db_path = first_existing([path for path in candidates if path])

    findings = []
    rules = analyse_rules(config, findings)
    connection = open_ledger(db_path)
    try:
        traffic = analyse_ledger(connection, rules["rules"], findings, max(1, args.top))
    finally:
        if connection is not None:
            connection.close()

    if args.json:
        payload = {
            "config": config_path,
            "ledger": db_path,
            "rules": {
                "business_rules_enabled": rules["business_rules_enabled"],
                "total": rules["total"],
                "enabled": rules["enabled"],
                "disabled": rules["disabled"],
                "islands_enabled": rules["islands_enabled"],
                "islands_disabled": rules["islands_disabled"],
                "items": [
                    {key: value for key, value in rule.items() if key != "index"}
                    for rule in rules["rules"]
                ],
            },
            "traffic": traffic,
            "findings": findings,
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(config_path, db_path, rules, traffic, findings)

    warnings = [finding for finding in findings if finding["severity"] == "warn"]
    if args.strict and warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
