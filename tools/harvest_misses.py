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
  python tools/harvest_misses.py propose [--emit-rust out.rs.txt]
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
DEFAULT_PROPOSALS = Path(__file__).parent / "lex_proposals.jsonl"
FEATURES_RS = Path(__file__).parent.parent / "src" / "ast" / "features.rs"

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
    # v6 protocol/semantic families
    "request_smuggling": "header_rule",
    "cache_poisoning": "header_rule",
    "oauth_oidc": "url_param_context",
    "saml": "mime_analyzer",
    "xslt_xquery": "xml_dtd",
    "dom_mxss": "markup_grammar",
    "csv_formula": "filename_rule",
    "archive_slip": "filename_rule",
    "redos": "url_param_context",
    "bidi_tag_chars": "markup_grammar",
    "appliance_cve_paths": "path_dictionary",
    "idn_homograph": "url_param_context",
    "smtp_raw": "mime_analyzer",
    "soap_action": "header_rule",
    "graphql_advanced": "graphql_analyzer",
    "mass_assignment": "json_operator",
    "business_logic": "json_operator",
    "atlassian_cve": "path_dictionary",
    "webdav_methods": "header_rule",
    "unicode_normalization": "url_param_context",
    "ansi_escape": "url_param_context",
    "log_injection": "url_param_context",
    "jwt_alg_dir": "jwt_analyzer",
}

RE_TT = re.compile(r"\\texttt\{([^}]+)\}")
RE_RULE = re.compile(r"(SAT-[A-Z]+-\d+|ISLAND-[A-Z0-9-]+)")
RE_ISLAND = re.compile(r"ISLAND-([A-Z0-9-]+)")
RE_VBIT = re.compile(r'"v(\d+)_')

# Detector skeleton per hint: where the new lexeme plugs into the engine.
DETECTOR_TEMPLATE = {
    "header_rule": "headers",          # iterate req.headers in tokenize_request
    "path_dictionary": "path",         # extend path regex / section E check
    "url_param_context": "normalized", # regex over normalized_text w/ param ctx
    "sql_grammar": "normalized",
    "markup_grammar": "normalized",
    "shell_grammar": "normalized",
    "crlf_context": "normalized",
    "mime_analyzer": "analyzer",
    "magic_bytes": "normalized",
    "xpath_grammar": "normalized",
    "template_grammar": "normalized",
    "ldap_filter": "normalized",
    "xml_dtd": "normalized",
    "filename_rule": "normalized",
    "cms_path": "path",
    "framework_signature": "path",
    "json_operator": "analyzer",
    "graphql_analyzer": "analyzer",
    "jwt_analyzer": "analyzer",
    "analyzer": "analyzer",
    "rule_tuning": "rule_tuning",
}

ISLAND_FOR_FAMILY = {
    "protocol_semantics": "ISLAND-PROTOCOL-SEMANTICS",
    "request_smuggling": "ISLAND-PROTOCOL-SEMANTICS",
    "cache_poisoning": "ISLAND-PROTOCOL-SEMANTICS",
    "webdav": "ISLAND-PROTOCOL-SEMANTICS",
    "oauth": "ISLAND-PROTOCOL-SEMANTICS",
    "saml": "ISLAND-PROTOCOL-SEMANTICS",
    "idn": "ISLAND-PROTOCOL-SEMANTICS",
    "soap": "ISLAND-PROTOCOL-SEMANTICS",
    "content_obfuscation": "ISLAND-CONTENT-OBFUSCATION",
    "unicode": "ISLAND-CONTENT-OBFUSCATION",
    "log_injection": "ISLAND-CONTENT-OBFUSCATION",
    "redos": "ISLAND-CONTENT-OBFUSCATION",
    "ansi": "ISLAND-CONTENT-OBFUSCATION",
    "bidi": "ISLAND-CONTENT-OBFUSCATION",
    "business_logic": "ISLAND-BUSINESS-RULES",
    "mass_assignment": "ISLAND-BUSINESS-RULES",
    "csv": "ISLAND-BUSINESS-RULES",
}


def next_free_bit() -> int:
    """Scan FEATURE_NAMES in features.rs for the highest used vN index."""
    if not FEATURES_RS.exists():
        return 80
    text = FEATURES_RS.read_text(encoding="utf-8")
    used = [int(m.group(1)) for m in RE_VBIT.finditer(text)]
    # bits are positional; the vN label matches the index for v0..v79
    return (max(used) + 1) if used else 80


def family_slug(family: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", family.lower()).strip("_")[:32] or "unknown"


def rust_fragment(prop: dict) -> str:
    """Emit a paste-ready Rust skeleton for the proposed lexeme."""
    tok = prop["token_field"]
    bit = prop["feature_bit"]
    vname = prop["feature_name"]
    island = prop["island"]
    rid = prop["rule_id"]
    det = prop["detector_kind"]
    pts = ", ".join(prop["injection_points"][:4]) or "(none)"
    excerpt = prop["payload_excerpt"][:120].replace('"', '\\"')
    det_hint = {
        "headers": "for (k, v) in &req.headers { /* match suspicious header names/values */ }",
        "path": 'let pq = format!("{}?{}", req.path, req.query_string); /* path regex check */',
        "normalized": "if RE_<NAME>.get().unwrap().is_match(&normalized) { tokens." + tok + " = true; tokens.active_token_names.push(\"<TOKEN_NAME>\".to_string()); }",
        "analyzer": "// dedicated analyzer module (see ast/jwt.rs, ast/graphql.rs)",
        "rule_tuning": "// narrow the offending rule instead of adding a lexeme",
    }.get(det, "// custom detector")
    return (
        f"// === PROPOSAL {prop['proposal_id']} :: {prop['family']} ===\n"
        f"// detector={det}  island={island}  points=[{pts}]\n"
        f"// sample: {excerpt}\n"
        f"//\n"
        f"// 1) src/ast/lexer.rs — LexicalTokens field:\n"
        f"//    pub {tok}: bool,\n"
        f"//\n"
        f"// 2) src/ast/lexer.rs — detection (kind '{det}'):\n"
        f"//    {det_hint}\n"
        f"//\n"
        f"// 3) src/ast/features.rs — FEATURE_NAMES + binarize:\n"
        f"//    \"{vname}\",\n"
        f"//    if tokens.{tok} {{ fv.set({bit}); }}\n"
        f"//\n"
        f"// 4) src/engine/sat_solver.rs — DeductionRule + eval arm:\n"
        f"//    rules.insert(\"{rid}\".to_string(), DeductionRule {{ ... island_id: \"{island}\" ... }});\n"
        f"//    if tokens.{tok} {{ ... rules.get(\"{rid}\") ... }}\n"
    )


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


def cmd_propose(args) -> int:
    """Cluster CANDIDATE misses by family and emit lexeme proposals.

    Each proposal carries: next free feature bit, token field name, detector
    kind, target island, rule id, injection points, and a Rust skeleton.
    Proposals are NEVER auto-applied — a human/agent reviews, implements the
    detector, replays against the benign ledger, then `promote` marks it.
    """
    db = load_db(Path(args.db))
    candidates = [r for r in db.values()
                  if r["kind"] == "miss_pattern" and r["status"] == "CANDIDATE"]
    if not candidates:
        print("no CANDIDATE misses to propose")
        return 0

    # Cluster by family; hits>=2 families get priority.
    by_family: dict[str, list[dict]] = {}
    for r in candidates:
        by_family.setdefault(r["family"], []).append(r)

    bit = next_free_bit()
    rule_n = 1
    proposals = []
    fragments = []
    for fam in sorted(by_family, key=lambda f: -sum(r["hits"] for r in by_family[f])):
        members = by_family[fam]
        hits = sum(r["hits"] for r in members)
        pts = sorted({p for r in members for p in r["injection_points"]})
        hint = DETECTOR_HINT.get(fam, members[0].get("detector_hint", "analyzer"))
        slug = family_slug(fam)
        token = f"has_{slug}_signal"[:48]
        vname = f"v{bit}_{slug[:24]}"
        # Island guess: explicit map first, else fall back by hint.
        island = next((ISLAND_FOR_FAMILY[k] for k in ISLAND_FOR_FAMILY
                       if k in fam.lower()), "ISLAND-PROTOCOL-SEMANTICS")
        prop = {
            "proposal_id": f"lex_{slug}_{bit}",
            "family": fam,
            "candidate_ids": [r["candidate_id"] for r in members],
            "hits": hits,
            "injection_points": pts[:8],
            "payload_excerpt": members[0].get("payload_excerpt", ""),
            "detector_kind": DETECTOR_TEMPLATE.get(hint, "analyzer"),
            "detector_hint": hint,
            "token_field": token,
            "feature_bit": bit,
            "feature_name": vname,
            "island": island,
            "rule_id": f"SAT-LEX-{rule_n:02d}",
            "status": "PROPOSED",
            "created": now(),
        }
        proposals.append(prop)
        fragments.append(rust_fragment(prop))
        bit += 1
        rule_n += 1

    out = Path(args.proposals)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for p in proposals:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    if args.emit_rust:
        Path(args.emit_rust).write_text("\n".join(fragments), encoding="utf-8")

    print(f"proposals: {len(proposals)} -> {out}")
    for p in proposals:
        print(f"  {p['proposal_id']:<28} bit={p['feature_bit']:<3} hits={p['hits']:<3} "
              f"{p['detector_kind']:<10} {p['island']:<28} {p['family'][:30]}")
    if args.emit_rust:
        print(f"rust skeletons -> {args.emit_rust}")
    print("\nnext: implement detector -> replay benign ledger -> harvest -> promote")
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

    pr = sub.add_parser("propose", help="cluster misses into lexeme proposals")
    pr.add_argument("--proposals", default=str(DEFAULT_PROPOSALS))
    pr.add_argument("--emit-rust", default=None, help="write Rust skeletons to file")
    pr.set_defaults(fn=cmd_propose)

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
