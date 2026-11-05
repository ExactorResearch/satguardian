#!/usr/bin/env python3
"""Build the shared request set used by every engine in the real comparison.

Each line of the output JSONL is one labelled HTTP request plus the provenance
needed to decide whether it may be used as a quality estimate. Adapters for the
external engines read exactly this file, so every engine sees the same bytes in
the same order.

The `split` field is the load-bearing one:

  in_sample_regression  - the engine was corrected against these cases, so a
                          perfect score here says nothing about generalisation.
  consumed_for_tuning   - same, and the batch is retired.
  held_out              - labelled before any engine call and not used for fixes.
                          Usable as a quality estimate only while it stays fresh;
                          tuning against it invalidates the file and forces a new
                          batch (see corpus/heldout_v2.json).

Only `held_out` records may feed the published comparison numbers.
"""

import argparse
import hashlib
import json
import pathlib
import sys

# A case in an unlabelled or contradictory file is a bug, not a judgement call,
# so refuse to emit rather than silently guessing.
SPLITS = {
    "independent_v1": {
        "split": "in_sample_regression",
        "why": (
            "Every miss and every false positive in this corpus was used to drive "
            "engine fixes, so it is a regression floor."
        ),
    },
    "heldout_v1": {
        "split": "consumed_for_tuning",
        "why": (
            "Written as a held-out batch, then spent as a tuning set before "
            "heldout_v2 existed. Retired; never quote it as generalisation."
        ),
    },
    "heldout_v2": {
        "split": "held_out",
        "why": (
            "Labels fixed before any engine call. Detection behaviour is unchanged "
            "since the 2026-11-04 measurement: the only later edit to src/engine "
            "was island-description and comment wording, verified with git show on "
            "2026-11-05. Re-measure and re-audit this field before each run."
        ),
    },
}

REQUIRED_REQUEST_KEYS = {"method", "path", "query", "body"}


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_batch(corpus_dir: pathlib.Path, name: str):
    path = corpus_dir / f"{name}.json"
    if not path.is_file():
        sys.exit(f"missing corpus file {path}; the comparison must not fall back to ad-hoc payloads")
    raw = path.read_text(encoding="utf-8")
    return name, json.loads(raw), sha256(path), raw


def build_record(name: str, case: dict, source_sha: str) -> dict:
    for key in ("id", "category", "label", "request"):
        if key not in case:
            sys.exit(f"{name}: case {case.get('id', '?')} has no {key!r}")
    if case["label"] not in ("malicious", "benign"):
        sys.exit(f"{name}: case {case['id']} label {case['label']!r} is not malicious/benign")
    req = case["request"]
    missing = REQUIRED_REQUEST_KEYS - set(req)
    if missing:
        sys.exit(f"{name}: case {case['id']} request is missing {sorted(missing)}")
    if case["label"] == "benign" and case["category"] != "benign":
        sys.exit(f"{name}: case {case['id']} is labelled benign but categorised {case['category']!r}")
    if case["label"] == "malicious" and case["category"] == "benign":
        sys.exit(f"{name}: case {case['id']} is labelled malicious but categorised benign")

    meta = SPLITS[name]
    return {
        "case_id": f"{name}/{case['id']}",
        "corpus": name,
        "corpus_version": case.get("version"),
        "split": meta["split"],
        "split_reason": meta["why"],
        "corpus_sha256": source_sha,
        "label": case["label"],
        "category": case["category"],
        "note": case.get("note", ""),
        "request": {
            "method": req["method"],
            "path": req["path"],
            "query": req["query"],
            "body": req["body"],
            "headers": {k.lower(): v for k, v in (req.get("headers") or {}).items()},
        },
    }


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[3]
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus-dir", default=str(root / "corpus"))
    ap.add_argument(
        "--out",
        default=str(pathlib.Path(__file__).resolve().parent.parent / "corpus" / "unified_v1.jsonl"),
    )
    ap.add_argument(
        "--include-split",
        action="append",
        default=[],
        choices=sorted({m["split"] for m in SPLITS.values()}),
        help="Restrict the request set to these splits (default: all three, so the "
        "regression floor and the held-out estimate stay visibly separate).",
    )
    args = ap.parse_args()

    corpus_dir = pathlib.Path(args.corpus_dir)
    records = []
    batches = []
    for name in sorted(SPLITS):
        loaded_name, data, digest, _ = load_batch(corpus_dir, name)
        if args.include_split and SPLITS[name]["split"] not in args.include_split:
            continue
        batches.append(
            {
                "corpus": loaded_name,
                "file": f"corpus/{loaded_name}.json",
                "sha256": digest,
                "declared_version": data.get("version"),
                "created": data.get("created"),
                "split": SPLITS[name]["split"],
                "case_count": len(data["cases"]),
                "attack_count": sum(1 for c in data["cases"] if c["label"] == "malicious"),
                "control_count": sum(1 for c in data["cases"] if c["label"] == "benign"),
            }
        )
        for case in data["cases"]:
            records.append(build_record(loaded_name, case, digest))

    ids = [r["case_id"] for r in records]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        sys.exit(f"duplicate case ids would double-count in every engine: {dupes}")

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    print(f"wrote {len(records)} cases to {out}")
    for b in batches:
        print(
            f"  {b['corpus']:16s} {b['split']:21s} "
            f"{b['attack_count']:3d} attacks / {b['control_count']:3d} controls  sha256={b['sha256'][:12]}"
        )
    held_out = sum(1 for r in records if r["split"] == "held_out")
    print(f"  usable as a quality estimate (held_out): {held_out} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
