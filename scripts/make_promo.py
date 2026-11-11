"""Generate SATGuardian promo banners (medium OG + thumbnails) with PIL."""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "promo")
os.makedirs(OUT, exist_ok=True)

# Palette matching mkdocs-material slate/indigo/cyan theme
BG_TOP = (15, 23, 42)      # slate-900
BG_BOT = (30, 41, 59)      # slate-800
INDIGO = (99, 102, 241)    # indigo-500
CYAN = (34, 211, 238)      # cyan-400
WHITE = (248, 250, 252)
MUTED = (148, 163, 184)    # slate-400
CARD = (30, 41, 59, 200)

FONT_DIR = r"C:\Windows\Fonts"

def font(name, size):
    path = os.path.join(FONT_DIR, name)
    return ImageFont.truetype(path, size) if os.path.exists(path) else ImageFont.load_default()

def vgradient(size, top, bot):
    img = Image.new("RGB", size, top)
    px = img.load()
    w, h = size
    for y in range(h):
        t = y / max(h - 1, 1)
        r = int(top[0] + (bot[0] - top[0]) * t)
        g = int(top[1] + (bot[1] - top[1]) * t)
        b = int(top[2] + (bot[2] - top[2]) * t)
        for x in range(w):
            px[x, y] = (r, g, b)
    return img

def shield(draw, cx, cy, s, color):
    """Draw a shield outline + checkmark, centered at (cx, cy), size s."""
    w = s * 0.62
    top = cy - s * 0.55
    bot = cy + s * 0.55
    pts = [
        (cx - w / 2, top + s * 0.12),
        (cx - w / 2, top + s * 0.30),
        (cx, top),
        (cx + w / 2, top + s * 0.30),
        (cx + w / 2, top + s * 0.12),
        (cx + w / 2 * 0.82, bot - s * 0.10),
        (cx, bot),
        (cx - w / 2 * 0.82, bot - s * 0.10),
    ]
    draw.polygon(pts, outline=color, width=max(3, s // 40))
    # checkmark
    cxs, cys = cx - s * 0.10, cy + s * 0.02
    draw.line([(cxs - s * 0.10, cys), (cxs - s * 0.02, cys + s * 0.10),
               (cxs + s * 0.16, cys - s * 0.14)], fill=color, width=max(4, s // 28))

def chip(draw, xy, text, fnt, fg=CYAN, bg=CARD):
    x, y = xy
    bbox = draw.textbbox((0, 0), text, font=fnt)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    pad = 14
    draw.rounded_rectangle([x, y, x + tw + pad * 2, y + th + pad * 2],
                           radius=10, fill=bg, outline=fg, width=2)
    draw.text((x + pad, y + pad - bbox[1]), text, font=fnt, fill=fg)
    return tw + pad * 2, th + pad * 2

# ---------------- Medium / OG banner: 1200x630 ----------------
W, H = 1200, 630
img = vgradient((W, H), BG_TOP, BG_BOT).convert("RGBA")
d = ImageDraw.Draw(img)

# accent bars
for i, color in enumerate([INDIGO, CYAN]):
    d.rounded_rectangle([60 + i * 14, H - 120, 200 + i * 14, H - 108],
                        radius=6, fill=color)

# shield + title block (left)
shield(d, 140, 210, 150, CYAN)
f_title = font("segoeuib.ttf", 96)
f_tag = font("segoeui.ttf", 40)
f_sub = font("segoeui.ttf", 30)
f_small = font("segoeui.ttf", 24)
f_chip = font("segoeuib.ttf", 26)

d.text((250, 130), "SATGuardian", font=f_title, fill=WHITE)
d.text((252, 250), "The WAF That Can", font=f_tag, fill=CYAN)
d.text((252, 300), "Prove Its Work", font=f_tag, fill=CYAN)
d.text((252, 380), "Deterministic, auditable security", font=f_sub, fill=MUTED)
d.text((252, 425), "decision layer — self-hosted, Rust.", font=f_sub, fill=MUTED)

# stat chips (right side)
chips = [
    ("82.0% recall vs Aegis (CRS suite)", CYAN),
    ("0.5% FPR vs 22.9% (665 benign)", INDIGO),
    ("92.9% union coverage", CYAN),
]
cx = 640
cy = 140
for text, color in chips:
    w, h = chip(d, (cx, cy), text, f_chip, fg=color)
    cy += h + 22

d.text((60, H - 96), "github.com/ExactorResearch/satguardian", font=f_small, fill=MUTED)
d.text((60, H - 60), "exactorresearch.github.io/satguardian", font=f_small, fill=MUTED)

img.convert("RGB").save(os.path.join(OUT, "satguardian-banner-1200x630.png"))

# ---------------- Thumbnail: 512x512 ----------------
T = 512
img2 = vgradient((T, T), BG_TOP, BG_BOT).convert("RGBA")
d2 = ImageDraw.Draw(img2)
# border ring
d2.rounded_rectangle([10, 10, T - 10, T - 10], radius=36, outline=CYAN, width=4)
shield(d2, T // 2, 190, 200, CYAN)
f_t = font("segoeuib.ttf", 52)
f_t2 = font("segoeui.ttf", 30)
f_t3 = font("segoeuib.ttf", 26)

# center text
tb = d2.textbbox((0, 0), "SATGuardian", font=f_t)
d2.text(((T - (tb[2] - tb[0])) / 2, 340), "SATGuardian", font=f_t, fill=WHITE)
tb2 = d2.textbbox((0, 0), "The WAF That Can", font=f_t2)
d2.text(((T - (tb2[2] - tb2[0])) / 2, 410), "The WAF That Can", font=f_t2, fill=CYAN)
tb3 = d2.textbbox((0, 0), "Prove Its Work", font=f_t2)
d2.text(((T - (tb3[2] - tb3[0])) / 2, 450), "Prove Its Work", font=f_t2, fill=CYAN)
tb4 = d2.textbbox((0, 0), "Auditable decisions, bit by bit", font=f_t3)
d2.text(((T - (tb4[2] - tb4[0])) / 2, 505), "Auditable decisions, bit by bit", font=f_t3, fill=MUTED)

img2.convert("RGB").save(os.path.join(OUT, "satguardian-thumb-512.png"))
img2.convert("RGB").resize((300, 300), Image.LANCZOS).save(os.path.join(OUT, "satguardian-thumb-300.png"))
img2.convert("RGB").resize((150, 150), Image.LANCZOS).save(os.path.join(OUT, "satguardian-thumb-150.png"))

print("done ->", OUT)
for f in sorted(os.listdir(OUT)):
    print(" ", f)
