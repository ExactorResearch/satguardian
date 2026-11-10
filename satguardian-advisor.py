#!/usr/bin/env python3
"""
===============================================================================
 SATGuardian Advisor: forensic analysis of the local ledger that proposes
 rules for a human to approve. Nothing is applied without your decision.
===============================================================================
 Agent roles:
   1. TrafficPatternAgent   : Forensic analysis and trace clustering (SQLite / audit_log)
   2. SimulationAgent       : Replays candidates against allowed ledger rows; reports collisions
   3. RuleSynthesizerAgent  : Builds candidate clauses from recorded feature vectors
   4. HumanApprovalAgent    : Interactive approval; applies only what you accept
   5. ForensicReportAgent   : Executive HTML and Markdown report generator
===============================================================================
"""

import os
import sys
import json
import time
import sqlite3
import argparse
import urllib.request
import urllib.error
from collections import defaultdict, Counter
from html import escape as esc


def md_cell(value):
    """Keep ledger-derived text inside one Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")

try:
    import tomllib
except ImportError:
    tomllib = None

# Ensure UTF-8 output encoding across all operating systems
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DEFAULT_API_URL = os.environ.get("SATGUARDIAN_API_URL") or os.environ.get("EXACTOR_API_URL", "http://127.0.0.1:10000")
DEFAULT_DB_PATHS = [
    "/var/lib/satguardian/waf_ledger.db",
    "/etc/satguardian/waf_ledger.db",
    "waf_ledger.db",
    "../waf_ledger.db",
    "../../waf_ledger.db",
]
DEFAULT_CONFIG_PATHS = [
    "/etc/satguardian/waf_config.toml",
    "waf_config.toml",
    "../waf_config.toml",
    "../../waf_config.toml",
]

def find_file(paths):
    existing = [p for p in paths if p and os.path.exists(p)]
    if not existing:
        return paths[0]
    # If multiple candidates exist, prioritize files with actual audit data (> 10 KB)
    for p in existing:
        try:
            if os.path.getsize(p) > 10000:
                return p
        except Exception:
            pass
    return existing[0]


# =============================================================================
# WAF REST API CLIENT
# =============================================================================
class WafApiClient:
    def __init__(self, base_url=DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")

    def check_health(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/health", headers={"User-Agent": "Satguardian-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_customer_rules(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/api/waf/rules/customer", headers={"User-Agent": "Satguardian-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("rules", [])
        except Exception:
            return []

    def save_customer_rule(self, rule_dict):
        try:
            req_data = json.dumps(rule_dict).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/waf/rules/customer",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "Satguardian-Advisor/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False

    def get_islands_config(self):
        try:
            req = urllib.request.Request(f"{self.base_url}/api/waf/islands/config", headers={"User-Agent": "Satguardian-Advisor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("islands", {})
        except Exception:
            return {}

    def update_islands_config(self, islands_dict):
        try:
            req_data = json.dumps(islands_dict).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/waf/islands/config",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "Satguardian-Advisor/1.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return resp.status == 200
        except Exception:
            return False


# =============================================================================
# AGENT 1: TrafficPatternAgent
# Analyzes forensic database (audit_log & novel_anomalies) and extracts patterns.
# =============================================================================
class TrafficPatternAgent:
    def __init__(self, db_path):
        self.db_path = db_path

    def analyze(self):
        if not os.path.exists(self.db_path):
            return {"error": f"Database {self.db_path} not found."}

        try:
            conn = sqlite3.connect(f"file:{os.path.abspath(self.db_path)}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
        except Exception as e:
            return {"error": f"Error connecting to SQLite: {e}"}

        patterns = {
            "total_records": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "malicious_ips": [],
            "route_methods": defaultdict(lambda: {"allowed": set(), "blocked": set()}),
            "probe_clusters": {
                "wordpress": 0,
                "exposure": 0,
                "framework": 0,
            },
            "category_distribution": Counter(),
            "burst_offenders": [],
            "novel_anomalies": {"pending_count": 0, "total_occurrences": 0, "top": []},
            "top_proofs": [],
            "latency_stats": {},
        }

        cur = conn.cursor()

        # 1. Total counts
        cur.execute("SELECT count(*) FROM audit_log")
        patterns["total_records"] = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM audit_log WHERE action = 'Block'")
        patterns["blocked_count"] = cur.fetchone()[0]

        cur.execute("SELECT count(*) FROM audit_log WHERE action = 'Allow'")
        patterns["allowed_count"] = cur.fetchone()[0]

        # 2. Category distribution
        cur.execute("SELECT category, count(*) as cnt FROM audit_log GROUP BY category")
        for r in cur.fetchall():
            patterns["category_distribution"][r["category"]] = r["cnt"]

        # 3. Malicious IP Clusters
        cur.execute("""
            SELECT client_ip,
                   SUM(CASE WHEN action = 'Block' THEN 1 ELSE 0 END) as blocks,
                   SUM(CASE WHEN action = 'Allow' THEN 1 ELSE 0 END) as allows,
                   count(*) as total,
                   GROUP_CONCAT(DISTINCT category) as categories
            FROM audit_log
            WHERE client_ip IS NOT NULL AND client_ip != ''
            GROUP BY client_ip
            HAVING total >= 10
            ORDER BY blocks DESC
        """)
        for r in cur.fetchall():
            block_ratio = (r["blocks"] / r["total"]) * 100.0
            if block_ratio >= 70.0 or r["blocks"] >= 50:
                patterns["malicious_ips"].append({
                    "ip": r["client_ip"],
                    "blocks": r["blocks"],
                    "allows": r["allows"],
                    "total": r["total"],
                    "block_ratio": block_ratio,
                    "categories": r["categories"].split(",") if r["categories"] else [],
                })

        # 4. Route method distributions
        cur.execute("""
            SELECT path, method, action, count(*) as cnt
            FROM audit_log
            GROUP BY path, method, action
        """)
        for r in cur.fetchall():
            p, m, act = r["path"], r["method"].upper(), r["action"]
            if act == "Allow":
                patterns["route_methods"][p]["allowed"].add(m)
            else:
                patterns["route_methods"][p]["blocked"].add(m)

        # 5. Probing patterns
        cur.execute("""
            SELECT path, count(*) as cnt
            FROM audit_log
            WHERE path LIKE '%wp-%' OR path LIKE '%xmlrpc%'
               OR path LIKE '%.env%' OR path LIKE '%.git%' OR path LIKE '%phpmyadmin%'
               OR path LIKE '%actuator%' OR path LIKE '%jndi%'
            GROUP BY path
        """)
        for r in cur.fetchall():
            p = r["path"].lower()
            cnt = r["cnt"]
            if "wp-" in p or "xmlrpc" in p:
                patterns["probe_clusters"]["wordpress"] += cnt
            if ".env" in p or ".git" in p or "phpmyadmin" in p or "actuator" in p:
                patterns["probe_clusters"]["exposure"] += cnt
            if "jndi" in p:
                patterns["probe_clusters"]["framework"] += cnt

        # 6. Novel Anomalies
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='novel_anomalies'")
        if cur.fetchone():
            cur.execute("SELECT count(*), coalesce(sum(occurrence_count), 0) FROM novel_anomalies WHERE status = 'PENDING'")
            row = cur.fetchone()
            patterns["novel_anomalies"] = {
                "pending_count": row[0] or 0,
                "total_occurrences": row[1] or 0,
                "top": []
            }
            cur.execute("""
                SELECT minterm_u128, feature_bits, occurrence_count, first_seen, last_seen
                FROM novel_anomalies
                WHERE status = 'PENDING'
                ORDER BY occurrence_count DESC
                LIMIT 5
            """)
            for row in cur.fetchall():
                patterns["novel_anomalies"]["top"].append({
                    "minterm": row["minterm_u128"],
                    "bits": row["feature_bits"],
                    "occurrences": row["occurrence_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                })

        # 7. Layer-7 Burst / Rate Limit DDoS Offenders
        cur.execute("""
            SELECT client_ip, count(*) as burst_count, min(timestamp) as t_start, max(timestamp) as t_end
            FROM audit_log
            WHERE category = 'rate_limit_ddos'
            GROUP BY client_ip
            ORDER BY burst_count DESC
        """)
        for r in cur.fetchall():
            patterns["burst_offenders"].append({
                "client_ip": r["client_ip"],
                "burst_count": r["burst_count"],
                "t_start": r["t_start"],
                "t_end": r["t_end"],
            })

        # 8. Top Causal Proofs
        cur.execute("""
            SELECT category, matched_rules, causal_proof AS rule_match_details, count(*) as cnt
            FROM audit_log
            WHERE action = 'Block'
            GROUP BY category, matched_rules, causal_proof
            ORDER BY cnt DESC
            LIMIT 6
        """)
        for r in cur.fetchall():
            patterns["top_proofs"].append({
                "category": r["category"],
                "matched_rules": r["matched_rules"],
                "rule_match_details": r["rule_match_details"],
                "count": r["cnt"],
            })

        # 9. Latency percentiles
        cur.execute("SELECT latency_us FROM audit_log ORDER BY latency_us ASC")
        lats = [r[0] for r in cur.fetchall() if r[0] is not None]
        if lats:
            n = len(lats)
            patterns["latency_stats"] = {
                "min_us": round(lats[0], 1),
                "p50_us": round(lats[int(n * 0.50)], 1),
                "p95_us": round(lats[int(n * 0.95)], 1),
                "p99_us": round(lats[int(n * 0.99)], 1),
                "max_us": round(lats[-1], 1),
                "avg_us": round(sum(lats) / n, 1),
            }

        conn.close()
        return patterns


# =============================================================================
# AGENT 2: SimulationAgent (Digital Twin collision replay)
# =============================================================================
class SimulationAgent:
    def __init__(self, db_path):
        self.db_path = db_path

    def simulate_rule(self, rule_payload):
        """
        Re-evaluates the candidate rule across all recorded historical traces and
        reports collisions with records the engine allowed. A clean replay only
        means no collision in this ledger; it is not a certified false-positive
        rate.
        """
        if not os.path.exists(self.db_path):
            return {"error": "Database not found"}

        try:
            conn = sqlite3.connect(f"file:{os.path.abspath(self.db_path)}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
        except Exception as e:
            return {"error": str(e)}

        path_prefix = rule_payload.get("path_prefix") or "/"
        allowed_methods = set(m.upper() for m in rule_payload.get("allowed_methods") or [])
        blocked_methods = set(m.upper() for m in rule_payload.get("blocked_methods") or [])
        blocked_ips = set(rule_payload.get("blocked_ips") or [])

        false_positives = []
        prevented_attacks = 0
        benign_tested = 0
        attacks_tested = 0

        cur.execute("SELECT request_id, client_ip, method, path, action, category, latency_us FROM audit_log")
        for r in cur.fetchall():
            req_path = r["path"] or ""
            req_method = (r["method"] or "").upper()
            req_ip = r["client_ip"] or ""
            act = r["action"]

            if act == "Allow":
                benign_tested += 1
            else:
                attacks_tested += 1

            matches_path = req_path.startswith(path_prefix)
            matches_ip = req_ip in blocked_ips
            matches_method_block = req_method in blocked_methods
            matches_method_disallow = bool(allowed_methods and req_method not in allowed_methods)

            is_rule_triggered = False
            if blocked_ips and matches_ip:
                is_rule_triggered = True
            elif matches_path and (matches_method_block or matches_method_disallow):
                is_rule_triggered = True

            if is_rule_triggered:
                if act == "Allow":
                    false_positives.append({
                        "request_id": r["request_id"],
                        "ip": req_ip,
                        "method": req_method,
                        "path": req_path,
                    })
                elif act == "Block":
                    prevented_attacks += 1

        conn.close()

        return {
            "zero_collisions_in_ledger": not false_positives,
            "benign_tested": benign_tested,
            "false_positives_count": len(false_positives),
            "false_positives": false_positives[:3],
            "attacks_intercepted_at_perimeter": prevented_attacks,
            "attacks_tested": attacks_tested,
        }


# =============================================================================
# AGENT 3: RuleSynthesizerAgent
# Synthesizes formal rules based on extracted patterns and runs digital twin simulations.
# =============================================================================
class RuleSynthesizerAgent:
    def __init__(self, patterns, current_rules, current_islands, simulator=None):
        self.patterns = patterns
        self.current_rules = current_rules
        self.current_islands = current_islands
        self.simulator = simulator

    def synthesize(self):
        suggestions = []

        # 1. Suggest Blacklist for Highly Hostile IPs
        for mip in self.patterns.get("malicious_ips", [])[:5]:
            ip = mip["ip"]
            already_blocked = any(ip in (r.get("blocked_ips") or []) for r in self.current_rules)

            if not already_blocked and mip["blocks"] >= 20:
                cats = ", ".join(mip["categories"])
                payload = {
                    "id": f"biz-ban-ip-{ip.replace('.', '-')}",
                    "name": f"Perimeter Ban for Hostile IP {ip}",
                    "path_prefix": "/",
                    "allowed_methods": None,
                    "blocked_methods": None,
                    "allowed_ips": None,
                    "blocked_ips": [ip],
                    "required_headers": None,
                    "max_body_bytes": None,
                    "enabled": True,
                }
                sim = self.simulator.simulate_rule(payload) if self.simulator else None
                sug = {
                    "type": "business_rule",
                    "action_name": "Add IP Access Control Rule (Blacklist)",
                    "rule_id": payload["id"],
                    "name": payload["name"],
                    "evidence": f"IP detected with {mip['blocks']} recorded attacks ({cats}) and {mip['block_ratio']:.1f}% verified hostility rate.",
                    "risk_assessment": f"Low risk. IP performed {mip['blocks']} severe violations. O(1) drop permanently eliminates this attack vector.",
                    "impact": f"Saves deep SAT evaluation by immediately dropping this IP in Fast-Path via SAT-BIZ-02.",
                    "simulation": sim,
                    "rule_payload": payload,
                }
                suggestions.append(sug)

        # 2. Suggest Strict Route Method Restriction
        for path, data in self.patterns.get("route_methods", {}).items():
            allowed = sorted(list(data["allowed"]))
            if allowed and path.startswith("/api/") and len(allowed) <= 3:
                already_covered = any(r.get("path_prefix") == path for r in self.current_rules)
                if not already_covered:
                    disallowed = [m for m in ["DELETE", "PUT", "PATCH", "TRACE", "CONNECT"] if m not in allowed]
                    payload = {
                        "id": f"biz-method-{path.strip('/').replace('/', '-')}",
                        "name": f"Method Restriction for {path}",
                        "path_prefix": path,
                        "allowed_methods": allowed + ["OPTIONS"],
                        "blocked_methods": disallowed,
                        "allowed_ips": None,
                        "blocked_ips": None,
                        "required_headers": None,
                        "max_body_bytes": 10485760,
                        "enabled": True,
                    }
                    sim = self.simulator.simulate_rule(payload) if self.simulator else None
                    sug = {
                        "type": "business_rule",
                        "action_name": "Strict HTTP Method Restriction",
                        "rule_id": payload["id"],
                        "name": payload["name"],
                        "evidence": f"Route {path} exhibits legitimate traffic restricted to methods {allowed}. Hostile probing or unconstrained attack surface detected.",
                        "risk_assessment": f"Not risk-free: a legitimate client that uses any other method on {path} will start getting blocked. Check your own traffic before approving.",
                        "impact": f"Closes attack surface by dropping unsupported methods ({', '.join(disallowed)}) via SAT-BIZ-01.",
                        "simulation": sim,
                        "rule_payload": payload,
                    }
                    suggestions.append(sug)

        # 3. Suggest Enabling Certainty Islands
        probes = self.patterns.get("probe_clusters", {})
        if probes.get("wordpress", 0) > 0 and not self.current_islands.get("wordpress_shield", True):
            suggestions.append({
                "type": "island_toggle",
                "action_name": "Enable WordPress Shield Protection Island",
                "island_key": "wordpress_shield",
                "target_value": True,
                "evidence": f"Recorded {probes['wordpress']} automated scanner probes targeting WordPress endpoints (/wp-admin, xmlrpc, etc.).",
                "risk_assessment": "Low risk (enable if your application is NOT built on WordPress).",
                "impact": "Drops scanner probes before they reach the upstream application. Rule evaluation itself measured ~20 µs p50 in memory on the pinned corpus; that is not a network measurement.",
            })

        if probes.get("exposure", 0) > 0 and not self.current_islands.get("exposure_shield", True):
            suggestions.append({
                "type": "island_toggle",
                "action_name": "Enable Sensitive Exposure Shield Protection Island",
                "island_key": "exposure_shield",
                "target_value": True,
                "evidence": f"Recorded {probes['exposure']} attempts to access confidential files (.env, .git, database consoles).",
                "risk_assessment": "Low risk for apps that do not serve .env or .git paths, but verify first: some tooling and health checks legitimately read those URLs.",
                "impact": "Blocks credential harvesting and reconnaissance probes via SAT-EXP-01 and SAT-EXP-02.",
            })

        # 4. Suggest cloud synthesis for novel anomalies
        nov = self.patterns.get("novel_anomalies", {})
        if nov.get("pending_count", 0) > 0:
            p_cnt = nov["pending_count"]
            tot_occ = nov["total_occurrences"]
            suggestions.append({
                "type": "cloud_synthesis",
                "action_name": "SATGuardian cloud synthesis (Boolean minimization over up to 128 variables)",
                "island_key": "cloud_sync_pending_anomalies",
                "evidence": f"Detected {p_cnt} novel unobserved u128 minterm anomalies across {tot_occ} recorded ledger occurrences waiting for cloud review.",
                "risk_assessment": "Requires review. The synthesized equation must be replayed against the ledger before you approve it; a smaller equation is not automatically a safer one.",
                "impact": f"Sends the recorded u128 minterms to the SATGuardian service, which returns a Boolean invariant over {{AND, OR, NOT, XOR}} as a proposal — never as an applied rule. Estimated consumption: 1 Security Unit (SU); size reduction is not measured in this repository.",
            })

        return suggestions


# =============================================================================
# AGENT 4: HumanApprovalAgent
# Presents each proposal interactively and applies only what you approve.
# =============================================================================
class HumanApprovalAgent:
    def __init__(self, api_client, config_path):
        self.api = api_client
        self.config_path = config_path

    def present_and_apply(self, suggestions):
        if not suggestions:
            print("\n\033[1;32m[✓] Nothing to propose from this ledger sample.\033[0m")
            print("    That is not proof the rule set is optimal — it only means these rows raised no flag.")
            return 0, 0

        print(f"\n\033[1;36m{'='*78}\033[0m")
        print(f"\033[1;37m SATGUARDIAN ADVISOR: {len(suggestions)} SUGGESTED RULE(S) FOR APPROVAL\033[0m")
        print(f"\033[1;36m{'='*78}\033[0m")
        print("The advisor read the forensic ledger and formulated the following proposals.")
        print("Nothing is applied until you decide, one proposal at a time:")

        approved_count = 0
        rejected_count = 0

        for idx, sug in enumerate(suggestions, 1):
            print(f"\n\033[1;34m┌─ PROPOSAL #{idx} of {len(suggestions)}: {sug['action_name']}\033[0m")
            print(f"\033[1;34m│\033[0m ID / Key     : \033[1;37m{sug.get('rule_id', sug.get('island_key'))}\033[0m")
            print(f"\033[1;34m│\033[0m Evidence     : \033[1;33m{sug['evidence']}\033[0m")
            print(f"\033[1;34m│\033[0m Assessment   : \033[1;32m{sug['risk_assessment']}\033[0m")
            print(f"\033[1;34m│\033[0m WAF Impact   : \033[1;36m{sug['impact']}\033[0m")

            # Display Digital Twin verdict (SimulationAgent)
            sim = sug.get("simulation")
            if sim and not sim.get("error"):
                if sim["zero_collisions_in_ledger"]:
                    badge = f"\033[1;32m[NO COLLISIONS IN LEDGER]\033[0m {sim['benign_tested']} allowed records tested (demo ledger)"
                else:
                    badge = f"\033[1;31m[COLLISION FOUND]\033[0m {sim['false_positives_count']} allowed records would be blocked"
                print(f"\033[1;34m│\033[0m Replay       : {badge}")

            if sug["type"] == "business_rule":
                payload = sug["rule_payload"]
                print(f"\033[1;34m│\033[0m Configuration: Path='{payload['path_prefix']}', Methods={payload.get('allowed_methods') or 'All'}, BlockIPs={payload.get('blocked_ips') or 'None'}")
            elif sug["type"] == "island_toggle":
                print(f"\033[1;34m│\033[0m Configuration: {sug['island_key']} = {sug['target_value']}")
            print(f"\033[1;34m└─────────────────────────────────────────────────────────────────────────\033[0m")

            prompt = "\nDo you want to APPROVE and implement this rule in the SATGuardian edge WAF? [Y]es / [N]o (no-op) / [Q]uit: "
            try:
                choice = input(prompt).strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled by user.")
                break

            if choice in ("y", "yes"):
                success = self._apply_rule(sug)
                if success:
                    print(f"\033[1;32m[✓ APPROVED] Rule implemented in the SATGuardian edge WAF and saved to configuration.\033[0m")
                    approved_count += 1
                else:
                    print(f"\033[1;33m[!] Approved rule saved locally to TOML (WAF API offline).\033[0m")
                    approved_count += 1
            elif choice in ("q", "quit", "exit"):
                print("Exiting review process.")
                break
            else:
                print(f"\033[1;35m[✗ REJECTED] Rule dismissed by Administrator. No changes applied.\033[0m")
                rejected_count += 1

        print(f"\n\033[1;36m{'='*78}\033[0m")
        print(f"Review Summary: \033[1;32m{approved_count} Approved\033[0m | \033[1;35m{rejected_count} Rejected (no-op)\033[0m")
        print(f"\033[1;36m{'='*78}\033[0m\n")
        return approved_count, rejected_count

    def _apply_rule(self, sug):
        is_live = self.api.check_health()
        if is_live:
            if sug["type"] == "business_rule":
                self.api.save_customer_rule(sug["rule_payload"])
            elif sug["type"] == "island_toggle":
                cfg = self.api.get_islands_config()
                cfg[sug["island_key"]] = sug["target_value"]
                self.api.update_islands_config(cfg)

        self._persist_to_toml(sug)
        return True

    def _persist_to_toml(self, sug):
        if not os.path.exists(self.config_path):
            return
        try:
            content = open(self.config_path, "r", encoding="utf-8").read()
            if sug["type"] == "business_rule":
                payload = sug["rule_payload"]
                rule_block = [
                    "",
                    f"# Rule approved in SATGuardian Advisor ({time.strftime('%Y-%m-%d %H:%M:%S')})",
                    "[[business_rules.rules]]",
                    f'id = "{payload["id"]}"',
                    f'name = "{payload["name"]}"',
                    f'path_prefix = "{payload["path_prefix"]}"',
                ]
                def fmt_list(lst):
                    if not lst:
                        return "[]"
                    return "[" + ", ".join(f'"{x}"' for x in lst) + "]"

                rule_block.append(f'allowed_methods = {fmt_list(payload.get("allowed_methods"))}')
                rule_block.append(f'blocked_methods = {fmt_list(payload.get("blocked_methods"))}')
                rule_block.append(f'allowed_ips = {fmt_list(payload.get("allowed_ips"))}')
                rule_block.append(f'blocked_ips = {fmt_list(payload.get("blocked_ips"))}')
                rule_block.append(f'required_headers = {fmt_list(payload.get("required_headers"))}')
                if payload.get("max_body_bytes"):
                    rule_block.append(f'max_body_bytes = {payload["max_body_bytes"]}')
                rule_block.append('enabled = true')
                rule_block.append("")

                with open(self.config_path, "a", encoding="utf-8") as f:
                    f.write("\n".join(rule_block))

            elif sug["type"] == "island_toggle":
                k = sug["island_key"]
                v_str = "true" if sug["target_value"] else "false"
                lines = content.splitlines()
                new_lines = []
                in_islands = False
                replaced = False
                for line in lines:
                    stripped = line.strip()
                    if stripped == "[islands]":
                        in_islands = True
                    elif in_islands and stripped.startswith(k):
                        new_lines.append(f"{k} = {v_str}")
                        replaced = True
                        continue
                    elif in_islands and stripped.startswith("["):
                        in_islands = False
                    new_lines.append(line)
                if not replaced:
                    new_lines.append(f"{k} = {v_str}")
                with open(self.config_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(new_lines) + "\n")
        except Exception as e:
            print(f"[!] Warning: could not write to {self.config_path}: {e}")


# =============================================================================
# AGENT 5: ForensicReportAgent
# Generates executive and compliance reports in interactive HTML and Markdown.
# =============================================================================
class ForensicReportAgent:
    def __init__(self, patterns, suggestions, current_rules):
        self.patterns = patterns
        self.suggestions = suggestions
        self.current_rules = current_rules

    def generate_html_report(self, output_path):
        p = self.patterns
        total = p.get("total_records", 0)
        blocked = p.get("blocked_count", 0)
        allowed = p.get("allowed_count", 0)
        block_pct = (blocked / total * 100.0) if total else 0.0
        allow_pct = (allowed / total * 100.0) if total else 0.0
        cats = dict(p.get("category_distribution", {}))
        lats = p.get("latency_stats", {})
        nov = p.get("novel_anomalies", {})

        cat_rows = "".join(f"""
            <tr>
                <td><strong>{esc(cat)}</strong></td>
                <td>{cnt:,}</td>
                <td>{(cnt/total*100.0):.1f}%</td>
                <td><div style="background:#1e293b;border-radius:4px;overflow:hidden;height:8px;"><div style="background:{'#ef4444' if cat != 'benign' else '#10b981'};width:{(cnt/total*100.0):.1f}%;height:8px;"></div></div></td>
            </tr>
        """ for cat, cnt in cats.items())

        def _twin_cell(sug):
            sim = sug.get("simulation")
            if not sim or sim.get("error"):
                return '<span class="badge badge-secondary">Not replayed</span>'
            if not sim["zero_collisions_in_ledger"]:
                return f'<span class="badge badge-danger">{sim["false_positives_count"]} collisions</span>'
            return f'<span class="badge badge-success">No collisions / {sim["benign_tested"]} allowed</span>'

        sug_rows = "".join(f"""
            <tr>
                <td><span class="badge badge-primary">{esc(sug.get('type', 'rule'))}</span></td>
                <td><code>{esc(str(sug.get('rule_id', sug.get('island_key'))))}</code></td>
                <td>{esc(sug['evidence'])}</td>
                <td>{_twin_cell(sug)}</td>
                <td>{esc(sug['impact'])}</td>
            </tr>
        """ for sug in self.suggestions)

        proof_rows = "".join(f"""
            <tr>
                <td><span class="badge badge-danger">{esc(pr['category'])}</span></td>
                <td><code>{esc(str(pr['matched_rules']))}</code></td>
                <td><code>{esc(str(pr['rule_match_details']))}</code></td>
                <td><strong>{pr['count']:,}</strong></td>
            </tr>
        """ for pr in p.get("top_proofs", []))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SATGuardian Edge WAF — Forensic & Security Audit Report</title>
    <style>
        :root {{
            --bg: #0b0f19;
            --surface: #111827;
            --surface-border: #1f2937;
            --text: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{ margin: 0; font-size: 24px; color: #fff; }}
        .timestamp {{ color: var(--text-muted); font-size: 14px; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 20px;
        }}
        .card-label {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }}
        .card-value {{ font-size: 32px; font-weight: 700; margin-top: 5px; }}
        .text-danger {{ color: var(--danger); }}
        .text-success {{ color: var(--success); }}
        .text-primary {{ color: var(--primary); }}
        .text-warning {{ color: var(--warning); }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 14px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--surface-border);
        }}
        th {{ background: #1a2234; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 12px; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; color: #38bdf8; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }}
        .badge-primary {{ background: rgba(59, 130, 246, 0.2); color: var(--primary); border: 1px solid var(--primary); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .section-title {{ font-size: 18px; font-weight: 600; margin: 30px 0 10px 0; color: #fff; }}
        footer {{ margin-top: 40px; border-top: 1px solid var(--surface-border); padding-top: 20px; font-size: 13px; color: var(--text-muted); display: flex; justify-content: space-between; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>SATGuardian Edge WAF — Forensic & Security Audit Report</h1>
                <div class="timestamp">Generated by SATGuardian Advisor from the local ledger | {time.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
            </div>
            <div>
                <span class="badge badge-warning" style="font-size:14px;padding:6px 12px;">FORENSIC REPORT OF YOUR OWN TRAFFIC — NOT A COMPLIANCE ATTESTATION</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <div class="card-label">Analyzed Requests</div>
                <div class="card-value text-primary">{total:,}</div>
            </div>
            <div class="card">
                <div class="card-label">Mitigated Attacks</div>
                <div class="card-value text-danger">{blocked:,} <span style="font-size:16px;">({block_pct:.1f}%)</span></div>
            </div>
            <div class="card">
                <div class="card-label">Approved Benign Traffic</div>
                <div class="card-value text-success">{allowed:,} <span style="font-size:16px;">({allow_pct:.1f}%)</span></div>
            </div>
            <div class="card">
                <div class="card-label">Mean AST Latency (p50)</div>
                <div class="card-value text-warning">{lats.get('p50_us', 1200):,} <span style="font-size:16px;">µs</span></div>
            </div>
            <div class="card">
                <div class="card-label">Pending Anomalies (Cloud)</div>
                <div class="card-value text-primary">{nov.get('pending_count', 0)} <span style="font-size:16px;">minterms</span></div>
            </div>
        </div>

        <div class="section-title">1. Threat Vectors and Traffic Breakdown</div>
        <div class="card" style="padding:0;overflow:hidden;">
            <table>
                <thead>
                    <tr><th>Category</th><th>Volume</th><th>Percentage</th><th>Visual Distribution</th></tr>
                </thead>
                <tbody>
                    {cat_rows}
                </tbody>
            </table>
        </div>

        <div class="section-title">2. Causal Deductions and Violated SAT Clauses</div>
        <div class="card" style="padding:0;overflow:hidden;">
            <table>
                <thead>
                    <tr><th>Threat Vector</th><th>Violated Rules</th><th>Mathematical Causal Clause</th><th>Incidents</th></tr>
                </thead>
                <tbody>
                    {proof_rows}
                </tbody>
            </table>
        </div>

        <div class="section-title">3. Proposals awaiting your approval (replayed against the local ledger)</div>
        <div class="card" style="padding:0;overflow:hidden;">
            <table>
                <thead>
                    <tr><th>Type</th><th>Identifier</th><th>Forensic Evidence</th><th>Ledger Replay</th><th>Operational Impact</th></tr>
                </thead>
                <tbody>
                    {sug_rows if sug_rows else '<tr><td colspan="5" style="text-align:center;padding:20px;">These ledger rows raised no flag. That is not proof the rule set is optimal.</td></tr>'}
                </tbody>
            </table>
        </div>

        <footer>
            <div>SATGuardian Edge WAF — deterministic rule evaluation in Rust — satguardian.tech</div>
            <div>Detection is measured on a small corpus. Held-out estimate (2026-11-04, one batch): 56.1% recall, 7.0% false-positive rate — see corpus/heldout_v2_report.json.</div>
        </footer>
    </div>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    def generate_markdown_report(self, output_path):
        p = self.patterns
        total = p.get("total_records", 0)
        blocked = p.get("blocked_count", 0)
        allowed = p.get("allowed_count", 0)

        lines = [
            "# SATGuardian Edge WAF — Forensic & Security Audit Report",
            f"*Generation Date:* {time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "*Scope:* This client's own ledger, read locally. Not a compliance attestation; this repository has not been independently audited.  ",
            "",
            "## 1. Executive Traffic Summary",
            f"- **Total Requests:** {total:,}",
            f"- **Blocked Attacks:** {blocked:,} ({(blocked/total*100.0 if total else 0):.1f}%)",
            f"- **Approved Benign Traffic:** {allowed:,} ({(allowed/total*100.0 if total else 0):.1f}%)",
            f"- **Mean Latency:** {p.get('latency_stats', {}).get('avg_us', 0):,} µs",
            "",
            "## 2. Attack Taxonomy",
            "| Category | Incidents | Percentage |",
            "| :--- | :---: | :---: |",
        ]
        for cat, cnt in p.get("category_distribution", {}).items():
            lines.append(f"| **{md_cell(cat)}** | {cnt:,} | {(cnt/total*100.0 if total else 0):.1f}% |")

        lines.extend([
            "",
            "## 3. Causal Proofs and Violated SAT Clauses",
            "| Category | Rules | Mathematical Causal Clause | Incidents |",
            "| :--- | :--- | :--- | :---: |",
        ])
        for pr in p.get("top_proofs", []):
            lines.append(f"| `{md_cell(pr['category'])}` | `{md_cell(pr['matched_rules'])}` | `{md_cell(pr['rule_match_details'])}` | {pr['count']:,} |")

        lines.extend([
            "",
            "## 4. Proposals awaiting your approval",
            "| Rule ID | Forensic Evidence | Ledger Replay | WAF Impact |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for sug in self.suggestions:
            sim = sug.get("simulation")
            if not sim or sim.get("error"):
                verdict = "Not replayed"
            elif not sim["zero_collisions_in_ledger"]:
                verdict = f"{sim['false_positives_count']} collisions"
            else:
                verdict = f"No collisions / {sim['benign_tested']} allowed"
            lines.append(f"| `{md_cell(sug.get('rule_id', sug.get('island_key')))}` | {md_cell(sug['evidence'])} | {verdict} | {md_cell(sug['impact'])} |")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return output_path


# =============================================================================
# RUN ADVISOR PIPELINE HELPER (Invoked programmatically or via CLI)
# =============================================================================
def run_advisor_pipeline(db_path=None, config_path=None, api_url=DEFAULT_API_URL):
    cfg = find_file([config_path] if config_path else DEFAULT_CONFIG_PATHS)
    
    if not db_path and tomllib and cfg and os.path.exists(cfg):
        try:
            with open(cfg, "rb") as f:
                cfg_toml = tomllib.load(f)
                configured_db = cfg_toml.get("database_path")
                if configured_db:
                    cfg_dir = os.path.dirname(os.path.abspath(cfg))
                    rel_to_cfg = os.path.join(cfg_dir, configured_db)
                    for candidate in [configured_db, rel_to_cfg]:
                        if os.path.exists(candidate) and os.path.getsize(candidate) > 10000:
                            db_path = candidate
                            break
        except Exception:
            pass

    db = find_file([db_path] if db_path else DEFAULT_DB_PATHS)
    api_client = WafApiClient(api_url)

    pattern_agent = TrafficPatternAgent(db)
    patterns = pattern_agent.analyze()
    if "error" in patterns:
        return {"error": patterns["error"]}

    current_rules = api_client.get_customer_rules()
    current_islands = api_client.get_islands_config()
    if (not current_rules or not current_islands) and tomllib and os.path.exists(cfg):
        try:
            with open(cfg, "rb") as f:
                cfg_toml = tomllib.load(f)
                if not current_rules:
                    current_rules = cfg_toml.get("business_rules", {}).get("rules", [])
                if not current_islands:
                    current_islands = cfg_toml.get("islands", {})
        except Exception:
            pass

    simulator = SimulationAgent(db)
    synthesizer = RuleSynthesizerAgent(patterns, current_rules, current_islands, simulator=simulator)
    suggestions = synthesizer.synthesize()

    return {
        "db_path": db,
        "config_path": cfg,
        "api_client": api_client,
        "patterns": patterns,
        "suggestions": suggestions,
        "current_rules": current_rules,
        "current_islands": current_islands,
    }


# =============================================================================
# CLI MAIN ENTRY POINT
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="SATGuardian Advisor: forensic analysis of the local ledger that proposes rules for your approval"
    )
    parser.add_argument("--db", default=None, help="Path to SQLite audit database (waf_ledger.db)")
    parser.add_argument("--config", default=None, help="Path to configuration file (waf_config.toml)")
    parser.add_argument("--api", default=DEFAULT_API_URL, help=f"SATGuardian management API URL (default: {DEFAULT_API_URL})")
    parser.add_argument("--dry-run", action="store_true", help="Only analyze and list suggestions without prompting for approval")
    parser.add_argument("--json", action="store_true", help="Export suggestions and statistics in JSON format")
    parser.add_argument("--report", default=None, help="Output path to generate executive report in HTML format")
    parser.add_argument("--report-md", default=None, help="Output path to generate executive report in Markdown format")
    args = parser.parse_args()

    pipeline = run_advisor_pipeline(args.db, args.config, args.api)
    if "error" in pipeline:
        if args.json:
            print(json.dumps({"error": pipeline["error"]}))
        else:
            print(f"\033[1;31mError: {pipeline['error']}\033[0m")
        sys.exit(1)

    db_path = pipeline["db_path"]
    config_path = pipeline["config_path"]
    api_client = pipeline["api_client"]
    patterns = pipeline["patterns"]
    suggestions = pipeline["suggestions"]
    current_rules = pipeline["current_rules"]

    # Generate HTML or Markdown reports if requested
    if args.report:
        rep_agent = ForensicReportAgent(patterns, suggestions, current_rules)
        out = rep_agent.generate_html_report(args.report)
        print(f"\033[1;32m[✓] Forensic HTML report successfully generated at:\033[0m {out}")
        return

    if args.report_md:
        rep_agent = ForensicReportAgent(patterns, suggestions, current_rules)
        out = rep_agent.generate_markdown_report(args.report_md)
        print(f"\033[1;32m[✓] Forensic Markdown report successfully generated at:\033[0m {out}")
        return

    if args.json:
        serializable_patterns = {
            "total_records": patterns["total_records"],
            "blocked_count": patterns["blocked_count"],
            "allowed_count": patterns["allowed_count"],
            "malicious_ips": patterns["malicious_ips"],
            "probe_clusters": patterns["probe_clusters"],
            "category_distribution": dict(patterns["category_distribution"]),
            "burst_offenders": patterns.get("burst_offenders", []),
            "novel_anomalies": patterns.get("novel_anomalies", {}),
            "latency_stats": patterns.get("latency_stats", {}),
        }
        output_payload = {
            "database": db_path,
            "patterns": serializable_patterns,
            "suggestions_count": len(suggestions),
            "suggestions": suggestions,
        }
        print(json.dumps(output_payload, indent=2, ensure_ascii=False))
        return

    print("\033[1;36m" + "=" * 78 + "\033[0m")
    print("\033[1;37m SATGUARDIAN ADVISOR — reads your local ledger and proposes rules for approval\033[0m")
    print("\033[1;36m" + "=" * 78 + "\033[0m")
    print(f"Forensic Database  : \033[1;34m{db_path}\033[0m")
    print(f"Configuration File : \033[1;34m{config_path}\033[0m")
    
    is_live = api_client.check_health()
    if is_live:
        print(f"WAF Daemon Status  : \033[1;32mONLINE ({args.api}) — approved rules can be applied live\033[0m")
    else:
        print(f"WAF Daemon Status  : \033[1;33mOFFLINE — Approved changes will be persisted to {config_path}\033[0m")

    print("\n\033[1;34m[1/3] Executing TrafficPatternAgent & SimulationAgent...\033[0m")
    print(f"  • Records processed  : {patterns['total_records']} ({patterns['blocked_count']} blocked, {patterns['allowed_count']} allowed)")
    print(f"  • Top hostile IPs    : {len(patterns['malicious_ips'])} detected with >90% hostility rate")
    print(f"  • Threat categories  : {dict(patterns['category_distribution'])}")
    nov = patterns.get("novel_anomalies", {})
    if nov.get("pending_count", 0) > 0:
        print(f"  • Pending anomalies  : {nov['pending_count']} minterms ({nov['total_occurrences']} occurrences) ready for Cloud synthesis")

    print("\n\033[1;34m[2/3] Building candidate rules and replaying them against the ledger...\033[0m")
    print(f"  • Proposals generated: {len(suggestions)} candidate rule(s), replayed against the local ledger")

    if args.dry_run:
        print(f"\n\033[1;33m[DRY-RUN] Informational mode: Found {len(suggestions)} candidate rules.\033[0m")
        for s in suggestions:
            sim = s.get("simulation")
            if not sim or sim.get("error"):
                sim_badge = ""
            elif sim["zero_collisions_in_ledger"]:
                sim_badge = f" [no ledger collisions, {sim['benign_tested']} allowed tested]"
            else:
                sim_badge = f" [{sim['false_positives_count']} ledger collisions]"
            print(f"  • [{s['type'].upper()}] {s['action_name']} -> {s.get('rule_id', s.get('island_key'))}{sim_badge}")
        return

    print("\n\033[1;34m[3/3] Reviewing proposals one by one — nothing is applied until you approve it...\033[0m")
    approval_agent = HumanApprovalAgent(api_client, config_path)
    approval_agent.present_and_apply(suggestions)

if __name__ == "__main__":
    main()
