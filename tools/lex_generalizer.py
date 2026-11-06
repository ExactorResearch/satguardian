#!/usr/bin/env python3
"""Lex generalizer: learn SAT clause candidates from feature-bit dumps.

This is the data-driven half of the dead-zone -> certainty-island loop.
`satbench --dump-features` emits the exact v0..vN bitmask the engine computed
for every corpus case. This tool trains an interpretable model (sklearn
decision tree — the same veto-judge idea as CascadeMetaClassifier) over those
bitmasks, extracts every root-to-leaf conjunction, and keeps ONLY the clauses
that fire on zero benign controls.

Output: learned-clause proposals in the same shape the cloud sync-simplify
path consumes (required_mask / expected_bits over feature indices), plus a
human-readable Rust fragment. Nothing is auto-applied — promotion still goes
through replay + human approval (`harvest_misses.py promote`).

Usage:
  # 1) dump features for every corpus you want in the training set
  satbench --corpus <c>.jsonl --out <v>.jsonl \
      --dump-features benchmarks/real_comparative/features/<name>.jsonl
  # 2) learn clauses
  python tools/lex_generalizer.py learn \
      --features benchmarks/real_comparative/features/*.jsonl \
      --out tools/learned_clauses.jsonl --emit-rust tools/learned_clauses.rs.txt
"""
import argparse
import json
import re
import sys
from pathlib import Path

import numpy as np

FEATURES_RS = Path(__file__).parent.parent / "src" / "ast" / "features.rs"
RE_VNAME = re.compile(r'"v(\d+)_([a-z0-9_]+)"')


def load_feature_names() -> list[str]:
    """FEATURE_NAMES is positional: array index == feature bit index."""
    text = FEATURES_RS.read_text(encoding="utf-8")
    names = [None] * 128
    for m in RE_VNAME.finditer(text):
        idx = int(m.group(1))
        if idx < 128:
            names[idx] = f"v{idx}_{m.group(2)}"
    # v0..v9 have no underscore suffix in some entries; fill gaps defensively
    for i, n in enumerate(names):
        if n is None:
            names[i] = f"v{i}"
    return names


def load_jsonl(path: Path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def collect(paths: list[str]):
    """Merge feature dumps; dedupe by case_id (later files win)."""
    rows = {}
    for p in paths:
        for rec in load_jsonl(Path(p)):
            if rec.get("label") in ("malicious", "benign"):
                if "bits" not in rec:  # u128 arrives as lo/hi halves
                    rec["bits"] = (rec.get("bits_hi", 0) << 64) | rec.get("bits_lo", 0)
                rows[rec["case_id"]] = rec
    return list(rows.values())


def bits_to_columns(bits: int, n_bits: int = 80):
    return [(bits >> i) & 1 for i in range(n_bits)]


def tree_paths(tree, n_bits: int):
    """Yield (conditions, value) for every leaf of a fitted DecisionTree.

    conditions: list of (bit_index, required_value) — the Boolean conjunction
    the path encodes. sklearn thresholds are 0.5 for binary features.
    """
    t = tree.tree_
    stack = [(0, [])]
    while stack:
        node, conds = stack.pop()
        if t.children_left[node] == t.children_right[node]:
            yield conds, int(t.value[node].argmax())
            continue
        feat = t.feature[node]
        thr = t.threshold[node]
        # binary feature: <=0.5 -> bit 0, >0.5 -> bit 1
        left_val = 0 if thr < 0.75 else 1
        right_val = 1 - left_val
        stack.append((t.children_left[node], conds + [(feat, left_val)]))
        stack.append((t.children_right[node], conds + [(feat, right_val)]))


def clause_mask(conds):
    """(required_mask, expected_bits) for the dynamic-clause evaluator."""
    mask = 0
    expect = 0
    for bit, val in conds:
        mask |= 1 << int(bit)
        if val:
            expect |= 1 << int(bit)
    return int(mask), int(expect)


def cmd_learn(args) -> int:
    from sklearn.tree import DecisionTreeClassifier

    names = load_feature_names()
    rows = collect(args.features)
    if args.misses_only:
        # Learn only what the engine currently misses: attacks the engine did
        # NOT block. Benign rows stay complete — a candidate clause must fire
        # on zero benign controls, blocked or not.
        rows = [r for r in rows if r["label"] == "benign" or not r.get("blocked", True)]
    if not rows:
        print("no labelled feature rows found", file=sys.stderr)
        return 1

    n_bits = max(80, max(i for i, n in enumerate(names) if n != f"v{i}") + 1)
    X = np.array([bits_to_columns(r["bits"], n_bits) for r in rows], dtype=np.uint8)
    y = np.array([1 if r["label"] == "malicious" else 0 for r in rows], dtype=np.uint8)
    benign_idx = [i for i, r in enumerate(rows) if r["label"] == "benign"]
    mal_idx = [i for i, r in enumerate(rows) if r["label"] == "malicious"]

    print(f"rows={len(rows)} attacks={len(mal_idx)} benign={len(benign_idx)} bits={n_bits}")

    clf = DecisionTreeClassifier(
        max_depth=args.depth,
        min_samples_leaf=args.min_leaf,
        class_weight="balanced",
        random_state=42,
    )
    clf.fit(X, y)

    # Evaluate every leaf conjunction against the FULL benign set: a clause is
    # only a candidate when it fires on zero benign controls.
    proposals = []
    for conds, value in tree_paths(clf, n_bits):
        if value != 1 or not conds:
            continue  # only attack leaves with at least one condition
        mask, expect = clause_mask(conds)
        # benign safety: no benign row may satisfy the conjunction
        fp = 0
        tp = 0
        cats = {}
        for i, r in enumerate(rows):
            row = X[i]
            if all(row[b] == v for b, v in conds):
                if r["label"] == "benign":
                    fp += 1
                else:
                    tp += 1
                    cats[r.get("category", "?")] = cats.get(r.get("category", "?"), 0) + 1
        if fp > 0:
            continue
        top_cat = max(cats.items(), key=lambda kv: kv[1])[0] if cats else "mixed"
        proposals.append({
            "kind": "learned_clause",
            "status": "PROPOSED",
            "required_mask": mask,
            "expected_bits": expect,
            "conditions": [
                {"bit": int(b), "feature": names[int(b)] if int(b) < len(names) else f"v{int(b)}", "value": int(v)}
                for b, v in sorted(conds, key=lambda c: int(c[0]))
            ],
            "coverage_attacks": tp,
            "top_category": top_cat,
            "categories": cats,
            "fp_on_benign": 0,
            "train_rows": len(rows),
        })

    # Rank by coverage; dedupe identical masks.
    seen = set()
    uniq = []
    for p in sorted(proposals, key=lambda p: -p["coverage_attacks"]):
        if p["required_mask"] in seen:
            continue
        seen.add(p["required_mask"])
        p["rule_id"] = f"SAT-LEARN-{len(uniq) + 1:02d}"
        uniq.append(p)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for p in uniq:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    total_cov = sum(p["coverage_attacks"] for p in uniq)
    print(f"clauses learned: {len(uniq)}  total attack coverage {total_cov}/{len(mal_idx)}  "
          f"all with fp_on_benign=0 -> {out}")
    for p in uniq[: args.top]:
        cond = " & ".join(
            f"{c['feature']}={c['value']}" for c in p["conditions"]
        )
        print(f"  {p['rule_id']:<14} cov={p['coverage_attacks']:<4} {p['top_category']:<24} {cond[:90]}")

    if args.emit_rust:
        frag = []
        for p in uniq:
            frag.append(
                f"// LEARNED {p['rule_id']} mask={p['required_mask']:#x} expect={p['expected_bits']:#x} "
                f"cov={p['coverage_attacks']} cat={p['top_category']}\n"
                f"//   " + " & ".join(f"{c['feature']}={c['value']}" for c in p["conditions"]) + "\n"
            )
        Path(args.emit_rust).write_text("\n".join(frag), encoding="utf-8")
        print(f"rust notes -> {args.emit_rust}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    l = sub.add_parser("learn", help="learn FP-free clause candidates from feature dumps")
    l.add_argument("--features", nargs="+", required=True, help="feature dump JSONL files")
    l.add_argument("--out", default="tools/learned_clauses.jsonl")
    l.add_argument("--emit-rust", default=None)
    l.add_argument("--depth", type=int, default=5)
    l.add_argument("--min-leaf", type=int, default=3)
    l.add_argument("--misses-only", action="store_true",
                   help="train on unblocked attacks only (the real dead-zone backlog)")
    l.add_argument("--top", type=int, default=25)
    l.set_defaults(fn=cmd_learn)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
