#!/usr/bin/env python3
"""Convert ANSI terminal output to a PNG image."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
DEFAULT_BG = (9, 11, 18)
DEFAULT_FG = (231, 236, 248)


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


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: ansi2png.py input.ansi output.png", file=sys.stderr)
        return 2
    src = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    out = Path(sys.argv[2])
    font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
    if not Path(font).exists():
        font = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
    img = ansi_to_image(src, font)
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
