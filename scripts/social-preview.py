#!/usr/bin/env python3
"""Render site/assets/social-preview.png — the card every link to this
repository unfurls as, on GitHub and everywhere else.

    python3 scripts/social-preview.py

It is drawn rather than photographed, for the reason the tagline is short:
these are rendered at a fraction of their size, and a screenshot of a dashboard
is unreadable there. The name, the sentence and the score have to survive being
shrunk; everything else is texture.

Nothing here is invented. The palette is site/styles.css's :root, the mark is
the geometry of internal/ui/web/assets/mark.svg scaled rather than a second
drawing of it, the wordmark is heavy mono with negative tracking because that
is what .brand is, and the body is serif because --font-body is. The finding
ids are real ones, and internal/docs/fixtures_test.go holds them to that.

Uploading it is a manual step: GitHub has no API for the social preview.
Settings -> General -> Social preview. See AGENTS.md.
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG        = (0x07, 0x10, 0x0f)   # --bg
PANEL     = (0x10, 0x18, 0x16)   # --panel
LINE      = (0x31, 0x41, 0x3b)   # --line
TEXT      = (0xf5, 0xea, 0xd2)   # --text
PAPER_MUT = (0xc8, 0xbe, 0xa7)   # --paper-muted
MUTED     = (0x9a, 0xa8, 0x9f)   # --muted
ACCENT    = (0xd2, 0xbc, 0x74)   # --accent
BONE      = (0xc8, 0xcc, 0xd4)   # mark.svg
SAFE      = (0x98, 0xc3, 0x79)   # mark.svg

MONO  = "/home/seolcu/.local/share/fonts/JetBrainsMonoNLNerdFont-ExtraBold.ttf"
MONO_R= "/home/seolcu/.local/share/fonts/JetBrainsMonoNLNerdFont-Regular.ttf"
SERIF = "/usr/share/fonts/google-noto/NotoSerif-Regular.ttf"

img = Image.new("RGB", (W, H), BG)
d = ImageDraw.Draw(img)

def mark(x, y, size):
    """mark.svg at `size` px, from its own 48-unit coordinates."""
    u = size / 48.0
    def r(a, b, w, h, fill):
        d.rectangle([x + a*u, y + b*u, x + (a+w)*u, y + (b+h)*u], fill=fill)
    for b in (13.2, 22.5, 31.8):          # pins, left and right
        r(3.4, b, 6.6, 3, BONE); r(38, b, 6.6, 3, BONE)
    for a in (13.2, 22.5, 31.8):          # pins, top and bottom
        r(a, 3.4, 3, 6.6, BONE); r(a, 38, 3, 6.6, BONE)
    d.rounded_rectangle([x + 9.6*u, y + 9.6*u, x + 38.4*u, y + 38.4*u],
                        radius=2.4*u, outline=BONE, width=max(1, round(2.8*u)))
    d.ellipse([x + (14.8-1.8)*u, y + (14.8-1.8)*u,                 # pin-1 notch
               x + (14.8+1.8)*u, y + (14.8+1.8)*u], fill=BONE)
    r(17.4, 17.4, 13.2, 13.2, SAFE)       # the hardened core
    r(21.7, 21.7, 4.6, 4.6, BONE)         # the die

def tracked(draw, xy, text, font, fill, tracking):
    """Draw with letter-spacing; .brand sets -0.04em and the wordmark needs it."""
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, font=font, fill=fill)
        x += draw.textlength(ch, font=font) + tracking
    return x

PAD = 84
d.rectangle([0, 0, W, 6], fill=ACCENT)                    # a rule, as the site has

MARK = 104
mark(PAD, 96, MARK)

word = ImageFont.truetype(MONO, 104)
end = tracked(d, (PAD + MARK + 34, 92), "hostveil", word, TEXT, -104 * 0.04)

# The left column stops short of the panel; nothing is allowed to run under it.
COL = 800 - 48 - PAD

def wrapped(text, font, width):
    lines, cur = [], ""
    for word in text.split():
        trial = (cur + " " + word).strip()
        if d.textlength(trial, font=font) <= width:
            cur = trial
        else:
            lines.append(cur); cur = word
    if cur:
        lines.append(cur)
    return lines

tag = ImageFont.truetype(SERIF, 38)
y = 246
for line in wrapped("Guided security hardening for self-hosted Linux servers.", tag, COL):
    d.text((PAD, y), line, font=tag, fill=PAPER_MUT); y += 50

d.line([PAD, 384, PAD + COL, 384], fill=LINE, width=2)

small = ImageFont.truetype(SERIF, 27)
y = 414
for line in wrapped("Finds what an attacker would use, scores it out of 100, and "
                    "fixes it \u2014 with a preview, a backup, and one-command "
                    "rollback.", small, COL):
    d.text((PAD, y), line, font=small, fill=MUTED); y += 38

# The right column carries the one thing hostveil produces, in the shape it
# produces it. A card is read at a fraction of this size, so it has to be a
# number and a bar rather than a screenshot of a number and a bar.
GX, GY, GW = 800, 96, W - 800 - PAD
d.rounded_rectangle([GX, GY, GX + GW, GY + 436], radius=14, fill=PANEL, outline=LINE, width=2)

lbl = ImageFont.truetype(MONO_R, 22)
d.text((GX + 34, GY + 34), "SECURITY", font=lbl, fill=MUTED)

big = ImageFont.truetype(MONO, 116)
d.text((GX + 30, GY + 74), "72", font=big, fill=TEXT)
outof = ImageFont.truetype(MONO_R, 34)
d.text((GX + 30 + d.textlength("72", font=big) + 10, GY + 148), "/100", font=outof, fill=MUTED)

# Twelve cells, filled to the score, in the heat the TUI would use for it.
CELLS, CW, CH, GAP = 12, 22, 16, 6
bx, by = GX + 34, GY + 238
for i in range(CELLS):
    on = i < round(CELLS * 0.72)
    d.rectangle([bx + i * (CW + GAP), by, bx + i * (CW + GAP) + CW, by + CH],
                fill=SAFE if on else LINE)

d.text((GX + 34, GY + 282), "94 after fixes", font=lbl, fill=ACCENT)

rows = ImageFont.truetype(MONO_R, 21)
for n, (sev, colour, name) in enumerate((
        ("HIGH", (0xe0, 0x57, 0x57), "compose.ds018"),
        ("MED ", (0xd6, 0xae, 0x58), "ssh.passwordauth"),
        ("LOW ", MUTED, "sysctl.rp-filter"))):
    y = GY + 330 + n * 30
    d.text((GX + 34, y), sev, font=rows, fill=colour)
    d.text((GX + 34 + 66, y), name, font=rows, fill=PAPER_MUT)

chip = ImageFont.truetype(MONO_R, 24)
x = PAD
for label, colour in (("one binary", SAFE), ("no cloud account", SAFE), ("GPL-3.0", ACCENT)):
    w = d.textlength(label, font=chip)
    d.rounded_rectangle([x, 556, x + w + 34, 600], radius=8, fill=PANEL, outline=LINE, width=2)
    d.text((x + 17, 566), label, font=chip, fill=colour)
    x += w + 34 + 16

img.save("site/assets/social-preview.png")
print("site/assets/social-preview.png", img.size)
