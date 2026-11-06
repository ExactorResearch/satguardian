#!/usr/bin/env python3
"""Harvest benchmark misses/false-positives into a pattern-candidate ledger.

This is the seed of the "dead-zone -> certainty-island" pipeline: every miss is
a candidate detector pattern, every FP is evidence against an existing rule.
Candidates are NEVER auto-promoted — promotion requires replay validation and
human approval, then the pattern becomes a feature bit + compiled Boolean
clause (the regex may then be demoted to a cheap pre-filter or retired).

Usage:
  python tools/harvest_misses.py harvest --corpus <corpus.jsonl> --verdicts <verdicts.jsonl>
  python tools/harvest_misses.py report
  python tools/harvest_misses.py promote --id <candidate_id> --bit <N> --rule <RULE_ID> --by <name>
  python tools/harvest_misses.py reject --id <candidate_id>
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).parent / "pattern_candidates.jsonl"

# Coarse detector hint per attack family — where a promoted clause would live.
DETECTOR_HINT = {
    "sql_injection": "sql_grammar",
    "xss": "markup_grammar",
    "command_injection": "shell_grammar",
    "rce": "shell_grammar",
    "path_traversal": "path_regex",
    "ssrf": "url_param_context",
    "graphql_abuse": "graphql_analyzer",
    "jwt": "jwt_analyzer",
    "host_header_injection": "header_rule",
    "http_response_splitting": "crlf_context",
    "email_header_injection": "mime_analyzer",
    "deserialization": "magic_bytes",
    "xpath_injection": "xpath_grammar",
    "ssti": "template_grammar",
    "ldap_injection": "ldap_filter",
    "xxe": "xml_dtd",
    "malicious_upload": "filename_rule",
    "sensitive_exposure": "path_dictionary",
    "cms_wordpress": "cms_path",
    "framework_exploit": "framework_signature",
    "nosql_injection": "json_operator",
}

RE_TT = re.compile(r"\\texttt\{([^}]+)\}")
RE_RULE = re.compile(r"(SAT-[A-Z]+-\d+|ISLAND-[A-Z0-9-]+)")
RE_ISLAND = re.compile(r"ISLAND-([A-Z0-9-]+)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def injection_points(request: dict) -> list[str]:
    """Where the payload lands: query param names, JSON body keys, path, headers."""
    pts = []
    q = request.get("query") or ""
    for pair in q.split("&"):
        if "=" in pair:
            pts.append("q:" + pair.split("=", 1)[0])
        elif pair:
            pts.append("q:" + pair)
    body = request.get("body") or ""
    body = body.strip()
    if body.startswith("{"):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                pts.extend("b:" + str(k) for k in obj.keys())
        except Exception:
            pass
    if not pts and request.get("path"):
        pts.append("path:" + request["path"].rsplit("/", 1)[-1])
    for k in (request.get("headers") or {}).keys():
        pts.append("h:" + k.lower())
    return sorted(set(pts))[:8]


def payload_excerpt(request: dict, limit: int = 220) -> str:
    parts = [request.get("query") or "", request.get("body") or ""]
    for k, v in (request.get("headers") or {}).items():
        parts.append(f"{k}: {v}")
    text = " | ".join(p for p in parts if p)
    return text[:limit]


def cand_id(kind: str, family: str, points: list[str]) -> str:
    sig = f"{kind}|{family}|{','.join(points)}"
    return "cand_" + hashlib.sha1(sig.encode()).hexdigest()[:12]


def load_db(path: Path) -> dict[str, dict]:
    db = {}
    if path.exists():
        for rec in load_jsonl(path):
            db[rec["candidate_id"]] = rec
    return db


def save_db(path: Path, db: dict[str, dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rec in sorted(db.values(), key=lambda r: r["candidate_id"]):
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def upsert(db: dict[str, dict], rec: dict, case_id: str, is_fp: bool) -> None:
    cid = rec["candidate_id"]
    cur = db.get(cid)
    if cur is None:
        cur = {
            "candidate_id": cid,
            "kind": rec["kind"],
            "family": rec["family"],
            "detector_hint": rec.get("detector_hint", ""),
            "injection_points": rec.get("injection_points", []),
            "payload_excerpt": rec.get("payload_excerpt", ""),
            "status": "CANDIDATE",
            "hits": 0,
            "fp_count": 0,
            "seen_cases": [],
            "first_seen": now(),
            "last_seen": now(),
            "promoted": None,
            "notes": "",
        }
        db[cid] = cur
    cur["last_seen"] = now()
    if case_id not in cur["seen_cases"]:
        cur["seen_cases"].append(case_id)
    if is_fp:
        cur["fp_count"] += 1
    else:
        cur["hits"] += 1
    # keep the most informative excerpt
    if rec.get("payload_excerpt") and len(rec["payload_excerpt"]) > len(cur["payload_excerpt"]):
        cur["payload_excerpt"] = rec["payload_excerpt"]


def cmd_harvest(args) -> int:
    corpus = {c["case_id"]: c for c in load_jsonl(Path(args.corpus))}
    db = load_db(Path(args.db))
    n_miss = n_fp = 0
    for v in load_jsonl(Path(args.verdicts)):
        case = corpus.get(v["case_id"])
        if case is None:
            continue
        req = case.get("request", {})
        fam = case.get("category") or v.get("true_category") or "unknown"
        pts = injection_points(req)
        excerpt = payload_excerpt(req)

        if v["label"] == "malicious" and not v["blocked"]:
            n_miss += 1
            rec = {
                "candidate_id": cand_id("miss", fam, pts),
                "kind": "miss_pattern",
                "family": fam,
                "detector_hint": DETECTOR_HINT.get(fam, "analyzer"),
                "injection_points": pts,
                "payload_excerpt": excerpt,
            }
            upsert(db, rec, v["case_id"], is_fp=False)

        elif v["label"] in ("benign", "control") and v["blocked"]:
            n_fp += 1
            toks = RE_TT.findall(v.get("reason", ""))
            rules = sorted(set(RE_RULE.findall(v.get("reason", ""))))
            island = ""
            mi = RE_ISLAND.search(v.get("reason", ""))
            if mi:
                island = mi.group(0)
            fam = "+".join(sorted(set(toks) | set(rules) | ({island} if island else set()))) or "unknown_rule"
            rec = {
                "candidate_id": cand_id("fp", fam, pts),
                "kind": "fp_rule",
                "family": f"fp:{fam[:80]}",
                "detector_hint": "rule_tuning",
                "injection_points": pts,
                "payload_excerpt": excerpt,
            }
            upsert(db, rec, v["case_id"], is_fp=True)

    save_db(Path(args.db), db)
    print(f"harvested: {n_miss} misses, {n_fp} false-positives -> {args.db}")
    print(f"ledger: {len(db)} candidates "
          f"({sum(1 for r in db.values() if r['kind'] == 'miss_pattern')} miss, "
          f"{sum(1 for r in db.values() if r['kind'] == 'fp_rule')} fp)")
    return 0


def cmd_report(args) -> int:
    db = load_db(Path(args.db))
    if not db:
        print("empty ledger")
        return 0
    misses = [r for r in db.values() if r["kind"] == "miss_pattern"]
    fps = [r for r in db.values() if r["kind"] == "fp_rule"]
    misses.sort(key=lambda r: -r["hits"])
    fps.sort(key=lambda r: -r["fp_count"])

    print(f"{'id':<16} {'status':<10} {'hits':>5} {'fp':>4}  family / points")
    print("-" * 90)
    for r in misses[: args.top]:
        pts = ",".join(r["injection_points"][:3])
        print(f"{r['candidate_id']:<16} {r['status']:<10} {r['hits']:>5} {r['fp_count']:>4}  "
              f"{r['family']:<24} {pts}  [{r['detector_hint']}]")
    if fps:
        print("\nFALSE-POSITIVE RULES (tuning evidence):")
        for r in fps[: args.top]:
            print(f"{r['candidate_id']:<16} {r['status']:<10} {r['hits']:>5} {r['fp_count']:>4}  {r['family'][:70]}")
    return 0


def cmd_promote(args) -> int:
    db = load_db(Path(args.db))
    rec = db.get(args.id)
    if rec is None:
        print(f"unknown candidate {args.id}", file=sys.stderr)
        return 1
    rec["status"] = "PROMOTED"
    rec["promoted"] = {
        "feature_bit": args.bit,
        "rule_id": args.rule,
        "approved_by": args.by,
        "date": now(),
    }
    save_db(Path(args.db), db)
    print(f"promoted {args.id} -> bit {args.bit}, rule {args.rule}")
    return 0


def cmd_reject(args) -> int:
    db = load_db(Path(args.db))
    rec = db.get(args.id)
    if rec is None:
        print(f"unknown candidate {args.id}", file=sys.stderr)
        return 1
    rec["status"] = "REJECTED"
    save_db(Path(args.db), db)
    print(f"rejected {args.id}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=str(DEFAULT_DB), help="candidate ledger path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="ingest corpus+verdicts into the ledger")
    h.add_argument("--corpus", required=True)
    h.add_argument("--verdicts", required=True)
    h.set_defaults(fn=cmd_harvest)

    r = sub.add_parser("report", help="summarize the ledger")
    r.add_argument("--top", type=int, default=30)
    r.set_defaults(fn=cmd_report)

    p = sub.add_parser("promote", help="mark a candidate promoted (manual approval)")
    p.add_argument("--id", required=True)
    p.add_argument("--bit", type=int, required=True)
    p.add_argument("--rule", required=True)
    p.add_argument("--by", default="operator")
    p.set_defaults(fn=cmd_promote)

    j = sub.add_parser("reject", help="mark a candidate rejected")
    j.add_argument("--id", required=True)
    j.set_defaults(fn=cmd_reject)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
