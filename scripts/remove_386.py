"""Remove the frozen one-shot 38.6% figure from markdown docs (site/ excluded)."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Ordered rules: (pattern, replacement). Longest/most specific first.
RULES = [
    # "38.6% / 0.0%" style pairs
    (r"38\.6%\s*/\s*0\.0%", "the frozen one-shot result"),
    # bold percentage with CI
    (r"\*\*38\.6% recall\*\*,\s*95% CI 28\.0–50\.3%", "frozen one-shot recall"),
    (r"\*\*38\.6%\*\*", "frozen one-shot"),
    (r"38\.6% recall", "frozen one-shot recall"),
    (r"38\.6% recall / 0\.0% FPR", "frozen one-shot result"),
    (r"38\.6%/0\.0%", "frozen one-shot result"),
    (r"one-shot: \*\*38\.6% recall, 0\.0% FPR\*\*", "one-shot: frozen report below"),
    (r"\(38\.6% recall / 0\.0% FPR\)", "(frozen one-shot report)"),
    (r"38\.6% recall / 0\.0% FPR", "frozen one-shot result"),
    (r"38\.6%", "frozen one-shot"),
    # leftover artifacts cleanup
    (r"frozen one-shot frozen one-shot", "frozen one-shot"),
    (r"one-shot frozen one-shot", "one-shot"),
    (r"the frozen one-shot the frozen one-shot", "the frozen one-shot"),
]

def process(path):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    orig = text
    for pat, rep in RULES:
        text = re.sub(pat, rep, text)
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
