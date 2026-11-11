"""Round 2: fix awkward artifacts left by the 38.6% removal."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULES = [
    (r"frozen one-shot \*\*frozen one-shot recall / 0\.0% FPR\*\*", "frozen one-shot result"),
    (r"\*\*frozen one-shot recall on 70 attacks\*\* \(95% CI 28\.0–50\.3%\)", "frozen one-shot result on 70 attacks"),
    (r"\*\*frozen one-shot recall on 70 attacks\*\*, 95% CI 28\.0–50\.3%", "frozen one-shot result on 70 attacks"),
    (r"\*\*frozen one-shot recall \(95% CI 28\.0–50\.3%\)\*\*", "its frozen one-shot result"),
    (r"frozen one-shot \(27/70\), 95% CI 28\.0–50\.3%", "frozen one-shot (27/70)"),
    (r"freezes its one-shot estimate at the frozen one-shot result", "freezes its one-shot estimate in `heldout_v10_report.json`"),
    (r"was measured once \(the frozen one-shot result\)", "was measured once — frozen in `heldout_v10_report.json`"),
    (r"the frozen one-shot estimate is \*\*frozen one-shot recall\*\* on 70 attacks", "the frozen one-shot estimate is recorded in `heldout_v10_report.json`"),
]

def process(path):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    orig = text
    for pat, rep in RULES:
        text = re.sub(pat, rep, text)
    # CI for the removed estimate is now orphaned; drop it where it directly follows
    text = re.sub(r"\(95% CI 28\.0–50\.3%\)", "", text)
    text = re.sub(r", 95% CI 28\.0–50\.3%", "", text)
    if text != orig:
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        return True
    return False

changed = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in {"site", "target", ".git", "node_modules"}]
    for fn in filenames:
        if fn.endswith(".md"):
            p = os.path.join(dirpath, fn)
            if process(p):
                changed.append(os.path.relpath(p, ROOT))

print(f"{len(changed)} files updated")
for c in changed:
    print(" ", c)
