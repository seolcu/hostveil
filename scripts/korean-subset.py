#!/usr/bin/env python3
"""Rebuild site/assets/fonts/ — the Korean webfonts the Korean site is set in.

    pip install fonttools brotli
    python3 scripts/korean-subset.py

Why the site ships a font at all. The design is a serif: --font-body is
Georgia, and the labels, buttons, nav and finding rows are monospace. Neither
of those has a Hangul glyph, so on the Korean pages every Korean character was
drawn by whatever the reader's operating system happened to fall back to — and
the stack asked for the wrong things. It named "Noto Sans KR", which is the
Google Fonts name; the family a Linux distribution installs is "Noto Sans CJK
KR", so on Fedora every Korean entry in both stacks missed and the text landed
on the generic fallback. In the monospace stack that generic is a *monospace*
CJK face, which is how a page of Korean marketing copy — "셀프호스터를 위한
가이드형 보안 강화" in the eyebrow, every nav link, every card kicker, every
finding title — came to be set in fixed-width Hangul with 0.14em of extra
tracking on top. And where the stack did resolve, it resolved to a sans inside
a serif design, so the Korean read in a different voice from the English.

So: Noto Serif KR for the body, matching Georgia's weight — that is the whole
reason it won over Gowun Batang and Nanum Myeongjo, both of which are visibly
lighter than the Latin they share a line with, and this site mixes scripts in
almost every sentence ("hostveil은 …"). Noto Sans KR for the slots the Latin
sets in monospace, because a label is a label and Korean does not have a
monospace tradition to borrow from.

Why a subset. Korean is 11,172 syllables and the full face is megabytes. The
whole Korean site — 16 pages — uses 766 of them, so the subset is the site's
own repertoire and nothing else, which is what gets a serif weight down to
about 110KB. **This is why internal/docs/koreanfont_test.go exists**: a subset
is silent when it is wrong. Write one new Korean sentence with one syllable
that was not in the site when this ran, and that syllable alone falls back to
a system font mid-word — a different face, a different weight, at a size
nobody chose. It is invisible to anyone reviewing the diff and invisible to
anyone whose system font happens to look close enough. The manifest this
writes is what the test reads, so the build fails instead.

Hangul only. Every @font-face in site/korean.css carries a unicode-range of
the Hangul blocks, so Latin, digits and punctuation keep coming from Georgia
and from the monospace stack exactly as they do on the English pages, and an
English page — which contains three Hangul syllables, the 한국어 switcher —
downloads none of this. That is also why the subset drops the Latin the source
faces carry: unicode-range means it could never be reached.

Not byte-reproducible, deliberately. woff2 output depends on the fonttools and
brotli versions, so this is not wired into the `git diff --exit-code site/`
gate the way cmd/sitegen is. What is pinned is coverage, which does not depend
on either.
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
KO_HTML = ROOT / "site" / "ko"
OUT = ROOT / "site" / "assets" / "fonts"

# Pinned to a commit rather than to main: this has to fetch the same bytes in a
# year's time, and google/fonts rebuilds these files in place. The digest is
# checked as well, so a URL that starts answering with something else is loud
# rather than quietly baked into the next subset.
UPSTREAM = "https://github.com/google/fonts/raw/e1118da94a8cb00cf6d06cdac9ef13eb1e5c6ab7"

SOURCES = [
    {
        "family": "Noto Serif KR",
        "path": "ofl/notoserifkr/NotoSerifKR%5Bwght%5D.ttf",
        "sha256": "11f8d5de6f1b79195efba3828aaa2ec95c1178f5ae976fb23c8d53250a9938f3",
        "license": "ofl/notoserifkr/OFL.txt",
        "license_out": "NotoSerifKR-OFL.txt",
        "weights": [400, 700],
        "stem": "NotoSerifKR",
    },
    {
        "family": "Noto Sans KR",
        "path": "ofl/notosanskr/NotoSansKR%5Bwght%5D.ttf",
        "sha256": "194018e6b2b293a7964f037b25c0249ce1418bc9ab3c971060a03aa57861e252",
        "license": "ofl/notosanskr/OFL.txt",
        "license_out": "NotoSansKR-OFL.txt",
        "weights": [400, 700],
        "stem": "NotoSansKR",
    },
]

# The blocks site/korean.css declares as the unicode-range. Syllables are what
# modern Korean is actually written in; the jamo blocks are here so that a
# stray ㄱ or a decomposed syllable is covered rather than being the one
# character on the page in another face.
HANGUL_BLOCKS = [
    (0x1100, 0x11FF),  # Hangul Jamo
    (0x3130, 0x318F),  # Hangul Compatibility Jamo
    (0xA960, 0xA97F),  # Hangul Jamo Extended-A
    (0xAC00, 0xD7A3),  # Hangul Syllables
    (0xD7B0, 0xD7FF),  # Hangul Jamo Extended-B
]


def in_hangul(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in HANGUL_BLOCKS)


def site_hangul() -> list[str]:
    """Every Hangul codepoint the generated Korean site contains.

    The whole file is read, not just the text nodes: an aria-label and a title
    attribute are read aloud and shown in a tooltip, so a syllable there needs
    a glyph as much as one in a paragraph does.
    """
    pages = sorted(KO_HTML.rglob("*.html"))
    if not pages:
        sys.exit(f"no pages under {KO_HTML} — run `go run ./cmd/sitegen` first")
    seen: set[str] = set()
    for page in pages:
        seen.update(c for c in page.read_text(encoding="utf-8") if in_hangul(c))
    if not seen:
        sys.exit(f"{len(pages)} Korean pages and no Hangul in any of them; something is wrong")
    return sorted(seen)


def fetch(url: str, want: str | None, dest: pathlib.Path) -> bytes:
    print(f"  fetching {url.rsplit('/', 1)[-1]}")
    with urllib.request.urlopen(url) as r:  # noqa: S310 - pinned https URL
        blob = r.read()
    got = hashlib.sha256(blob).hexdigest()
    if want and got != want:
        sys.exit(
            f"{url}\n  expected sha256 {want}\n  got      sha256 {got}\n"
            "  Upstream changed. Look at what changed before bumping the digest:\n"
            "  a new version of the face means the shipped subset and the one this\n"
            "  builds are two different fonts under one name."
        )
    dest.write_bytes(blob)
    return blob


def run(*argv: str) -> None:
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"{argv[0]} failed:\n{proc.stdout}\n{proc.stderr}")


def main() -> None:
    for tool in ("fonttools", "pyftsubset"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            sys.exit(f"{tool} not found — pip install fonttools brotli")

    chars = site_hangul()
    print(f"{len(chars)} distinct Hangul codepoints across {len(list(KO_HTML.rglob('*.html')))} Korean pages")

    OUT.mkdir(parents=True, exist_ok=True)
    built: list[tuple[str, int]] = []

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = pathlib.Path(tmp)
        for src in SOURCES:
            print(f"{src['family']}:")
            vf = tmpdir / f"{src['stem']}-VF.ttf"
            fetch(f"{UPSTREAM}/{src['path']}", src["sha256"], vf)
            fetch(f"{UPSTREAM}/{src['license']}", None, OUT / src["license_out"])

            for weight in src["weights"]:
                static = tmpdir / f"{src['stem']}-{weight}.ttf"
                run("fonttools", "varLib.instancer", "-q", "-o", str(static), str(vf), f"wght={weight}")

                out = OUT / f"{src['stem']}-{weight}.woff2"
                run(
                    "pyftsubset",
                    str(static),
                    f"--output-file={out}",
                    "--flavor=woff2",
                    "--text=" + "".join(chars),
                    # Nothing here needs shaping: modern Korean is precomposed
                    # syllables, one codepoint to one glyph. Keeping the layout
                    # tables would keep the jamo composition machinery for jamo
                    # this site does not use.
                    "--layout-features=",
                    "--no-hinting",
                    "--drop-tables+=DSIG",
                    "--name-IDs=0,1,2,3,4,6,13,14",
                )
                built.append((out.name, out.stat().st_size))
                print(f"  {out.name}  {out.stat().st_size / 1024:.0f} KB")

    manifest = OUT / "coverage.txt"
    body = [
        "# Generated by scripts/korean-subset.py. Do not edit by hand.",
        "#",
        "# The Korean webfonts under site/assets/fonts/ carry exactly the Hangul",
        "# below and nothing else. internal/docs/koreanfont_test.go reads this file",
        "# and fails the build when the Korean site uses a syllable that is not in",
        "# it — which would otherwise be one character silently rendered by the",
        "# reader's system font in the middle of a word.",
        "#",
        "# Re-run the script after editing Korean copy in cmd/sitegen/content/ko/.",
        "",
        f"upstream {UPSTREAM}",
    ]
    for src in SOURCES:
        body.append(f"source {src['path'].replace('%5B', '[').replace('%5D', ']')} sha256:{src['sha256']}")
    for name, size in built:
        digest = hashlib.sha256((OUT / name).read_bytes()).hexdigest()
        body.append(f"font {name} {size} sha256:{digest}")
    body.append(f"codepoints {len(chars)}")
    body.append("")
    for i in range(0, len(chars), 64):
        body.append("".join(chars[i : i + 64]))
    body.append("")
    manifest.write_text("\n".join(body), encoding="utf-8")

    total = sum(size for _, size in built)
    print(f"\n{manifest.relative_to(ROOT)}: {len(chars)} codepoints, {total / 1024:.0f} KB of woff2 in total")


if __name__ == "__main__":
    main()
