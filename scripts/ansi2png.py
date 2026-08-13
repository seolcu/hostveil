#!/usr/bin/env python3
"""Convert ANSI terminal output to a PNG image."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")

# The ground and the default ink, which is to say: One Dark's Ink and Bone,
# the two roles internal/ui/theme gives hostveil's default theme.
#
# They have to come from somewhere, because a terminal capture does not carry
# them. A TUI does not paint its own background — it draws on whatever the
# terminal is already showing — and `tmux capture-pane` records the cells,
# not the window underneath them. So every glyph that leaves the colour at
# the terminal default arrives here as a bare `39`/`49`, and this file has to
# decide what those mean.
#
# It used to answer #090b12, a near-black that no theme in this project
# contains, so the screenshot showed hostveil's palette floating on a ground
# hostveil never draws. Anything reading the picture as "what it looks like
# on my machine" was reading a colour scheme that does not exist.
#
# HOSTVEIL_ANSI2PNG_BG and _FG override them, which is what a capture of a
# non-default theme needs — the values are in internal/ui/theme, one Ink and
# one Bone per theme.
DEFAULT_BG = (0x28, 0x2C, 0x34)  # onedark Ink
DEFAULT_FG = (0xC8, 0xCC, 0xD4)  # onedark Bone

# The 16 named ANSI colours, in the shades xterm uses for them.
ANSI_16 = (
    (0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0),
    (0, 0, 238), (205, 0, 205), (0, 205, 205), (229, 229, 229),
    (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0),
    (92, 92, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255),
)

# The levels the 6x6x6 cube quantises each channel to.
CUBE_LEVELS = (0, 95, 135, 175, 215, 255)


def parse_hex(value: str, what: str) -> tuple[int, int, int]:
    h = value.strip().lstrip("#")
    if len(h) != 6:
        raise SystemExit(f"ansi2png: {what} must be a #rrggbb colour, got {value!r}")
    try:
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    except ValueError:
        raise SystemExit(f"ansi2png: {what} must be a #rrggbb colour, got {value!r}") from None


def xterm256(index: int) -> tuple[int, int, int]:
    """One entry of the xterm-256 palette as RGB.

    This exists because a screenshot taken the honest way is a 256-colour
    screenshot. hostveil's subject is servers, servers are reached over SSH,
    SSH does not forward COLORTERM, and so colorprofile degrades the TUI to
    xterm-256 on very nearly every real session — the same fact
    internal/ui/tui/quantize_test.go holds the palettes to. A capture off a
    real host therefore arrives as `38;5;N`, and a renderer that understands
    only truecolor drops every colour on the floor and produces a monochrome
    picture of a colourful program.
    """
    if index < 16:
        return ANSI_16[index]
    if index < 232:
        index -= 16
        return (
            CUBE_LEVELS[(index // 36) % 6],
            CUBE_LEVELS[(index // 6) % 6],
            CUBE_LEVELS[index % 6],
        )
    grey = 8 + 10 * (index - 232)
    return (grey, grey, grey)


def parse_sgr(params: str, state: dict[str, object]) -> dict[str, object]:
    if params == "":
        params = "0"
    parts = [int(p) if p else 0 for p in params.split(";")]
    i = 0
    while i < len(parts):
        code = parts[i]
        if code == 0:
            state = {"fg": DEFAULT_FG, "bg": DEFAULT_BG, "bold": False, "strike": False, "faint": False}
        elif code == 1:
            state["bold"] = True
        elif code == 2:
            state["faint"] = True
        elif code == 9:
            state["strike"] = True
        elif code == 22:
            state["bold"] = False
        elif code == 39:
            state["fg"] = DEFAULT_FG
        elif code == 49:
            state["bg"] = DEFAULT_BG
        elif code == 38 and i + 4 < len(parts) and parts[i + 1] == 2:
            state["fg"] = (parts[i + 2], parts[i + 3], parts[i + 4])
            i += 4
        elif code == 48 and i + 4 < len(parts) and parts[i + 1] == 2:
            state["bg"] = (parts[i + 2], parts[i + 3], parts[i + 4])
            i += 4
        elif code == 38 and i + 2 < len(parts) and parts[i + 1] == 5:
            state["fg"] = xterm256(parts[i + 2])
            i += 2
        elif code == 48 and i + 2 < len(parts) and parts[i + 1] == 5:
            state["bg"] = xterm256(parts[i + 2])
            i += 2
        elif 30 <= code <= 37:
            state["fg"] = ANSI_16[code - 30]
        elif 40 <= code <= 47:
            state["bg"] = ANSI_16[code - 40]
        elif 90 <= code <= 97:
            state["fg"] = ANSI_16[code - 90 + 8]
        elif 100 <= code <= 107:
            state["bg"] = ANSI_16[code - 100 + 8]
        i += 1
    return state


def blend(fg: tuple[int, int, int], bg: tuple[int, int, int], faint: bool) -> tuple[int, int, int]:
    if not faint:
        return fg
    return tuple((f + b) // 2 for f, b in zip(fg, bg))


def ansi_to_image(text: str, font_path: str, font_size: int = 13) -> Image.Image:
    font = ImageFont.truetype(font_path, font_size)
    ascent, descent = font.getmetrics()
    line_h = ascent + descent + 2
    char_w = font.getlength("M")

    lines: list[list[tuple[str, dict[str, object]]]] = []
    for raw_line in text.splitlines():
        state: dict[str, object] = {"fg": DEFAULT_FG, "bg": DEFAULT_BG, "bold": False, "strike": False, "faint": False}
        spans: list[tuple[str, dict[str, object]]] = []
        pos = 0
        for match in SGR_RE.finditer(raw_line):
            if match.start() > pos:
                spans.append((raw_line[pos:match.start()], dict(state)))
            state = parse_sgr(match.group(1), state)
            pos = match.end()
        if pos < len(raw_line):
            spans.append((raw_line[pos:], dict(state)))
        lines.append(spans)

    width = max(int(char_w * 8), 80)
    for spans in lines:
        line_len = sum(len(seg) for seg, _ in spans)
        width = max(width, int(line_len * char_w) + 20)

    height = max(len(lines), 1) * line_h + 20
    img = Image.new("RGB", (width, height), DEFAULT_BG)
    draw = ImageDraw.Draw(img)

    y = 10
    for spans in lines:
        x = 10.0
        for segment, style in spans:
            fg = blend(style["fg"], style["bg"], bool(style["faint"]))  # type: ignore[arg-type]
            bg = style["bg"]  # type: ignore[assignment]
            for ch in segment:
                if ch == "\t":
                    x += char_w * 4
                    continue
                ch_w = font.getlength(ch)
                if bg != DEFAULT_BG:
                    draw.rectangle((x, y, x + ch_w, y + line_h), fill=bg)
                if style["strike"]:
                    draw.text((x, y), ch, font=font, fill=fg)
                    mid = y + line_h // 2
                    draw.line((x, mid, x + ch_w, mid), fill=fg, width=1)
                else:
                    draw.text((x, y), ch, font=font, fill=fg)
                x += ch_w
        y += line_h
    return img


# Where DejaVu Sans Mono actually lives, by packaging convention. The first
# entry is Debian's and was the only one this script knew, so it worked on the
# machine it was written on and raised "cannot open resource" everywhere else
# — including Fedora, where the same font is packaged under a different path.
# The published screenshot is rendered with this font, so falling back to
# whatever else is installed would silently change how the website looks.
FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",       # Debian, Ubuntu
    "/usr/share/fonts/dejavu-sans-mono-fonts/DejaVuSansMono.ttf",  # Fedora, RHEL
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",                 # Arch, older Fedora
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",                    # Arch (ttf-dejavu)
    "/opt/homebrew/share/fonts/DejaVuSansMono.ttf",               # macOS, homebrew
)


def resolve_font() -> str:
    """The font the published screenshot is rendered with, or an explanation.

    HOSTVEIL_ANSI2PNG_FONT overrides it, which is the escape hatch for a
    host that keeps its fonts somewhere none of the candidates name. It is
    not a default: rendering the site's screenshot in a different typeface
    is a change to how the website looks, and it should be something
    somebody asked for rather than something a missing package chose.
    """
    override = os.environ.get("HOSTVEIL_ANSI2PNG_FONT")
    if override:
        if not Path(override).exists():
            raise SystemExit(f"ansi2png: HOSTVEIL_ANSI2PNG_FONT={override} does not exist")
        return override
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    raise SystemExit(
        "ansi2png: DejaVu Sans Mono is not installed, and it is the font the\n"
        "published screenshot is rendered with. Install it:\n"
        "  Debian/Ubuntu  apt install fonts-dejavu-core\n"
        "  Fedora/RHEL    dnf install dejavu-sans-mono-fonts\n"
        "  Arch           pacman -S ttf-dejavu\n"
        "Or set HOSTVEIL_ANSI2PNG_FONT to a monospace .ttf, knowing that it\n"
        "changes how site/assets/tui.png looks."
    )


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: ansi2png.py input.ansi output.png", file=sys.stderr)
        return 2
    global DEFAULT_BG, DEFAULT_FG
    if bg := os.environ.get("HOSTVEIL_ANSI2PNG_BG"):
        DEFAULT_BG = parse_hex(bg, "HOSTVEIL_ANSI2PNG_BG")
    if fg := os.environ.get("HOSTVEIL_ANSI2PNG_FG"):
        DEFAULT_FG = parse_hex(fg, "HOSTVEIL_ANSI2PNG_FG")
    src = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    out = Path(sys.argv[2])
    img = ansi_to_image(src, resolve_font())
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
