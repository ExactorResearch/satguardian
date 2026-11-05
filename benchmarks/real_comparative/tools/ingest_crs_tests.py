#!/usr/bin/env python3
"""Convert the OWASP CRS regression suite into the shared comparison JSONL.

The CRS test suite is the only corpus here whose labels were not written by us:
each stage states which rule IDs the CRS authors expect to fire. That makes it
the natural cross-engine yardstick - every engine can be judged against the same
vendor-authored expectations.

Two honesty rules are baked in:

1. `expect_ids` non-empty is the ONLY shape we treat as a label. Stages that
   carry no `expect_ids` are emitted as `unlabelled` and scored by nobody,
   because the CRS repository does not document whether an absent list means
   "must not match" or simply "not asserted". Guessing would invent a negative
   test set out of ambiguous data.
2. This suite is in-sample for CRS - the rules were written to pass these tests
   - and out-of-sample for SATGuardian. A high CRS score here is a property of
   the corpus, not a result, so the harness reports it in a separate bucket.

Run it where the vendor clone lives:
    python3 ingest_crs_tests.py --crs-dir /var/tmp/satbench/vendor/coreruleset \
        --out /var/tmp/satbench/corpus/crs_v430.jsonl
"""

import argparse
import glob
import hashlib
import json
import os
import pathlib
import sys

import yaml

CORPUS = "crs_v430"
TAG = "v4.30.0"
COMMIT = "e03a4f6dabc7a30ebd8c52c97d28a154f590a48f"

# Files the operating environment refused to open during the 2026-11-05 build of
# this corpus. They are recorded rather than dropped silently: their rules then
# have zero coverage in the vendor suite and every score derived from it must be
# read with that gap in mind.
ENVIRONMENT_EXCLUDED = [
    "REQUEST-933-APPLICATION-ATTACK-PHP/933100.yaml",
    "REQUEST-933-APPLICATION-ATTACK-PHP/933111.yaml",
    "REQUEST-933-APPLICATION-ATTACK-PHP/933190.yaml",
    "RESPONSE-955-WEB-SHELLS/955260.yaml",
]


def split_uri(uri: str):
    if "?" in uri:
        path, query = uri.split("?", 1)
        return path, query
    return uri, ""


def main() -> int:
    here = pathlib.Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--crs-dir", default=os.path.expanduser("~/.local/share/satbench/vendor/coreruleset"))
    ap.add_argument("--out", default=str(here.parent / "corpus" / f"{CORPUS}.jsonl"))
    args = ap.parse_args()

    tests_root = os.path.join(args.crs_dir, "tests", "regression", "tests")
    if not os.path.isdir(tests_root):
        sys.exit(f"no CRS regression suite at {tests_root}; clone it first (see README.md)")

    files = sorted(glob.glob(os.path.join(tests_root, "*", "*.yaml")))
    stats = {"yaml": len(files), "unreadable": 0, "no_dict": 0, "stages": 0,
             "labelled_attack": 0, "unlabelled": 0, "skipped_encoded": 0}
    records = []
    seen_ids = set()

    for fpath in files:
        rel = os.path.relpath(fpath, tests_root).replace(os.sep, "/")
        try:
            doc = yaml.safe_load(open(fpath, encoding="utf-8"))
        except (OSError, yaml.YAMLError) as e:
            stats["unreadable"] += 1
            print(f"  excluida {rel}: {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if not isinstance(doc, dict) or not isinstance(doc.get("tests"), list):
            stats["no_dict"] += 1
            continue

        rule_file = os.path.basename(fpath)[: -len(".yaml")]
        rule_id = doc.get("rule_id", rule_file.split("-")[0])

        for test in doc["tests"]:
            if not isinstance(test, dict):
                continue
            stages = test.get("stages")
            if stages is None:
                stages = [test["stage"]] if isinstance(test.get("stage"), dict) else []
            for idx, stage in enumerate(stages):
                stats["stages"] += 1
                inp = stage.get("input") or {}
                if "encoded_request" in inp:
                    stats["skipped_encoded"] += 1
                    continue
                out = (stage.get("output") or {}).get("log") or {}
                expect_ids = out.get("expect_ids")
                labelled = isinstance(expect_ids, list) and len(expect_ids) > 0

                path, query = split_uri(str(inp.get("uri") or "/"))
                headers = {str(k).lower(): str(v)
                           for k, v in (inp.get("headers") or {}).items()
                           if str(k).lower() not in ("host", "port", "dest_addr")}
                case_id = f"{CORPUS}/{rule_file}/{test.get('test_id', 'x')}-{idx}"
                if case_id in seen_ids:
                    sys.exit(f"duplicate case_id {case_id}: the harness would double-count")
                seen_ids.add(case_id)

                if labelled:
                    stats["labelled_attack"] += 1
                    split, label = "vendor_in_sample", "malicious"
                else:
                    stats["unlabelled"] += 1
                    split, label = "unlabelled", "unlabelled"

                records.append({
                    "case_id": case_id,
                    "corpus": CORPUS,
                    "corpus_version": TAG,
                    "split": split,
                    "split_reason": (
                        f"Label authored by the OWASP CRS project in {rel}: the stage "
                        f"asserts rule ids {expect_ids}. In-sample for CRS, unseen by SATGuardian."
                        if labelled else
                        f"{rel} stage asserts no rule ids; CRS does not document whether that "
                        "means 'must not match', so it is scored by no engine."
                    ),
                    "vendor_source": {"project": "coreruleset", "tag": TAG, "commit": COMMIT,
                                      "file": rel, "rule_id": str(rule_id)},
                    "label": label,
                    "category": rule_file.split("-", 1)[0] if labelled else "unlabelled",
                    "note": str(test.get("desc", ""))[:300],
                    "expected_rule_ids": [str(i) for i in (expect_ids or [])],
                    "request": {
                        "method": str(inp.get("method") or "GET"),
                        "path": path,
                        "query": query,
                        "body": str(inp.get("data") or ""),
                        "headers": headers,
                    },
                })

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(json.dumps(r, ensure_ascii=False, sort_keys=True) for r in records) + "\n"
    with out.open("w", encoding="utf-8", newline="") as fh:
        fh.write(payload)

    print(f"CRS {TAG} ({COMMIT[:12]}) -> {out}")
    print(f"  archivos yaml      : {stats['yaml']}")
    print(f"  ilegibles          : {stats['unreadable']} (ver ENVIRONMENT_EXCLUDED)")
    print(f"  sin documento      : {stats['no_dict']}")
    print(f"  stages totales     : {stats['stages']}")
    print(f"  con etiqueta vendor: {stats['labelled_attack']}")
    print(f"  sin etiqueta       : {stats['unlabelled']} (excluidos de todo ratio)")
    print(f"  request codificado : {stats['skipped_encoded']} (no representable como HTTP plano)")
    print(f"  sha256 del JSONL   : {hashlib.sha256(payload.encode()).hexdigest()}")
    if stats["unreadable"] != len(ENVIRONMENT_EXCLUDED):
        print(f"  AVISO: se esperaban {len(ENVIRONMENT_EXCLUDED)} archivos excluidos por entorno, "
              f"hubo {stats['unreadable']}; la lista del README esta desactualizada")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
