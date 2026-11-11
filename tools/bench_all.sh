#!/bin/bash
# Usage: tools/bench_all.sh — runs CRS + all regression corpora, prints compact table
set -e
cd "$(dirname "$0")/.."
SB=../target/release/satbench.exe
mkdir -p benchmarks/real_comparative/results/tmp
$SB --corpus benchmarks/real_comparative/corpus/crs_v430.jsonl --out benchmarks/real_comparative/results/satguardian/verdicts_crs_v430.jsonl 2>/dev/null | grep SUMMARY_JSON | python -c "import json,sys; d=json.loads(sys.stdin.read().split('SUMMARY_JSON ',1)[1]); v=d['vendor_in_sample']; print(f'CRS {v[\"detected\"]}/{v[\"attacks\"]} = {v[\"detected\"]/v[\"attacks\"]*100:.1f}%')"
for c in unified_v1 heldout_v3 heldout_v4 heldout_v5 heldout_v6 heldout_v7; do
  f=benchmarks/real_comparative/corpus/$c.jsonl
  [ -f "$f" ] || continue
  $SB --corpus "$f" --out benchmarks/real_comparative/results/tmp/v_$c.jsonl >/dev/null 2>&1
  python -c "
import json
atk=det=ben=blk=0
for line in open('benchmarks/real_comparative/results/tmp/v_$c.jsonl',encoding='utf-8'):
    d=json.loads(line)
    if d.get('label')=='malicious': atk+=1; det+=d.get('blocked',False)
    elif d.get('label')=='benign': ben+=1; blk+=d.get('blocked',False)
print(f'$c recall {det/max(atk,1)*100:.1f} fpr {blk/max(ben,1)*100:.1f} fp {blk}')"
done
