#!/usr/bin/env python3
"""Render the brand images that live outside the website's own pages:

    site/assets/social-preview.png   the card every link to this repository
                                     unfurls as, on GitHub and everywhere else
    site/assets/banner-light.png     the README header, for GitHub's light theme
    site/assets/banner-dark.png      ... and its dark one
    site/assets/banner-ko-light.png  the same for README.ko.md, with the
    site/assets/banner-ko-dark.png   Korean line

    python3 scripts/social-preview.py

They are drawn rather than photographed, because each is rendered at a
fraction of its size: the name, the mark and one sentence have to survive
being shrunk, and nothing else is allowed on the card to compete with them.

Nothing here is invented. The palette is site/styles.css's two schemes (the
dark one is the dashboard's default theme), the mark is the geometry of
internal/ui/web/assets/mark.svg scaled rather than a second drawing of it,
and the sentence is the site's own headline.

Fonts are looked up with fc-match rather than named by path, so this runs on
any machine that has them: Inter for Latin (the closest open face to the
system fonts the site is set in), and Noto Sans KR for the Korean banners.
HOSTVEIL_FONT_SANS, HOSTVEIL_FONT_SANS_MEDIUM and HOSTVEIL_FONT_KO take a file
path instead, which is how to point it at a static instance of the variable
Noto Sans KR that scripts/korean-subset.py fetches.

Uploading the social preview is a manual step: GitHub has no API for it.
Settings -> General -> Social preview. See AGENTS.md.
"""
import os
import pathlib
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "assets"

# site/styles.css, both schemes. Bone and Safe are the mark's two roles.
DARK = dict(bg=(0x0B, 0x0B, 0x0C), text=(0xF5, 0xF5, 0xF7), muted=(0x98, 0x98, 0x9D),
            bone=(0xF5, 0xF5, 0xF7), safe=(0x3C, 0xCF, 0x7E))
LIGHT = dict(bg=(0xFB, 0xFB, 0xFD), text=(0x1D, 0x1D, 0x1F), muted=(0x6E, 0x6E, 0x73),
             bone=(0x1D, 0x1D, 0x1F), safe=(0x1F, 0x8F, 0x4E))

SLOGAN_EN = "Quiet security for the servers you run."
SLOGAN_KO = "서버 보안. 조용하게, 단단하게."
SUMMARY = ("Finds the security mistakes on a self-hosted Linux server, "
           "explains them plainly, and fixes them with a preview, a backup "
           "and rollback.")

SS = 2  # drawn at twice the size and scaled down, for smooth curves


def font_file(env, *patterns):
    if os.environ.get(env):
        return os.environ[env]
    for pattern in patterns:
        try:
            out = subprocess.run(["fc-match", "-f", "%{family}\t%{file}", pattern],
                                 capture_output=True, text=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            continue
        family, _, path = out.partition("\t")
        if pattern.split(":")[0].lower() in family.lower():
            return path
    sys.exit(f"no font for {patterns[0]}: install it, or set {env} to a font file")


SANS = font_file("HOSTVEIL_FONT_SANS", "Inter:style=SemiBold")
SANS_MEDIUM = font_file("HOSTVEIL_FONT_SANS_MEDIUM", "Inter:style=Medium")
MONO = font_file("HOSTVEIL_FONT_MONO", "JetBrains Mono", "DejaVu Sans Mono")


def mark(d, x, y, size, back, front, ground):
    """mark.svg at `size` px, from its own 48-unit coordinates.

    The back sheet is cut away around the front one; here the cut is drawn by
    painting the expanded front shape in the ground colour first, which is
    the same picture on a flat ground."""
    u = size / 48.0

    def rr(a, b, w, h, r, fill):
        d.rounded_rectangle([x + a * u, y + b * u, x + (a + w) * u, y + (b + h) * u],
                            radius=r * u, fill=fill)

    rr(5, 5, 26, 26, 8, back)
    rr(14, 14, 32, 32, 11, ground)
    rr(17, 17, 26, 26, 8, front)


def tracked(d, xy, text, font, fill, tracking):
    x, y = xy
    for ch in text:
        d.text((x, y), ch, font=font, fill=fill)
        x += d.textlength(ch, font=font) + tracking
    return x


def wrapped(d, text, font, width):
    lines, cur = [], ""
    for word in text.split():
        trial = (cur + " " + word).strip()
        if d.textlength(trial, font=font) <= width:
            cur = trial
        else:
            lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def canvas(w, h, p):
    img = Image.new("RGB", (w * SS, h * SS), p["bg"])
    return img, ImageDraw.Draw(img)


def save(img, name):
    w, h = img.size
    img.resize((w // SS, h // SS), Image.LANCZOS).save(OUT / name, optimize=True)
    print(f"site/assets/{name}", (w // SS, h // SS))


def social_preview():
    p = DARK
    W, H, PAD = 1280, 640, 96
    img, d = canvas(W, H, p)
    s = SS

    # The mark, very large and very faint, bleeding off the right edge: the
    # one bit of texture the card carries.
    ghost = Image.new("RGB", img.size, p["bg"])
    gd = ImageDraw.Draw(ghost)
    gm = 600 * s
    mark(gd, 820 * s, (H * s - gm) // 2, gm, p["bone"], p["bone"], p["bg"])
    img = Image.blend(img, ghost, 0.06)
    d = ImageDraw.Draw(img)

    m = 84
    mark(d, PAD * s, 112 * s, m * s, p["bone"], p["safe"], p["bg"])
    word = ImageFont.truetype(SANS, 84 * s)
    tracked(d, ((PAD + m + 26) * s, 108 * s), "hostveil", word, p["text"], -84 * s * 0.035)

    tag = ImageFont.truetype(SANS, 54 * s)
    y = 250
    for line in wrapped(d, SLOGAN_EN, tag, 760 * s):
        tracked(d, (PAD * s, y * s), line, tag, p["text"], -54 * s * 0.02)
        y += 66

    small = ImageFont.truetype(SANS_MEDIUM, 26 * s)
    y += 18
    for line in wrapped(d, SUMMARY, small, 760 * s):
        d.text((PAD * s, y * s), line, font=small, fill=p["muted"])
        y += 38

    url = ImageFont.truetype(MONO, 22 * s)
    d.text((PAD * s, (H - 74) * s), "github.com/seolcu/hostveil", font=url, fill=p["muted"])
    save(img, "social-preview.png")


def banner(p, name, slogan, tag_font):
    W, H, PAD = 1280, 320, 88
    img, d = canvas(W, H, p)
    s = SS
    m = 112
    mark(d, PAD * s, (H - m) // 2 * s, m * s, p["bone"], p["safe"], p["bg"])

    word = ImageFont.truetype(SANS, 92 * s)
    x = (PAD + m + 40) * s
    tracked(d, (x, 86 * s), "hostveil", word, p["text"], -92 * s * 0.035)
    tag = ImageFont.truetype(tag_font, 34 * s)
    d.text((x + 4 * s, 200 * s), slogan, font=tag, fill=p["muted"])
    save(img, name)


def main():
    social_preview()
    banner(LIGHT, "banner-light.png", SLOGAN_EN, SANS_MEDIUM)
    banner(DARK, "banner-dark.png", SLOGAN_EN, SANS_MEDIUM)
    ko = font_file("HOSTVEIL_FONT_KO", "Noto Sans KR:weight=500", "Noto Sans CJK KR:style=Medium")
    banner(LIGHT, "banner-ko-light.png", SLOGAN_KO, ko)
    banner(DARK, "banner-ko-dark.png", SLOGAN_KO, ko)


if __name__ == "__main__":
    main()
