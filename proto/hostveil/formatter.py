"""CLI report formatting."""

from __future__ import annotations

import os
import shutil
import sys
from collections import defaultdict

from .i18n import tr
from .models import Axis, Finding, ScoreReport, SEVERITY_ORDER, Severity


RESET = "\033[0m"
BOLD = "\033[1m"
FG_RED = "\033[31m"
FG_YELLOW = "\033[33m"
FG_GREEN = "\033[32m"
FG_ORANGE = "\033[38;5;208m"
FG_CYAN = "\033[36m"
FG_GRAY = "\033[90m"

# Unified diff: dark full-row highlights (true color). Light text on dark bg reads well on
# light or dark terminal themes; pad to terminal width so the fill runs edge-to-edge.
DIFF_BG_REMOVED = "\033[48;2;56;30;34m"
DIFF_FG_REMOVED = "\033[38;2;252;236;238m"
DIFF_BG_ADDED = "\033[48;2;26;52;40m"
DIFF_FG_ADDED = "\033[38;2;220;248;228m"

SEVERITY_COLORS = {
    Severity.CRITICAL: FG_RED,
    Severity.HIGH: FG_RED,
    Severity.MEDIUM: FG_YELLOW,
    Severity.LOW: FG_GREEN,
}

AXIS_DISPLAY_ORDER = (
    Axis.SENSITIVE_DATA,
    Axis.EXCESSIVE_PERMISSIONS,
    Axis.UNNECESSARY_EXPOSURE,
    Axis.UPDATE_RISK,
)


def should_use_color() -> bool:
    """Use ANSI styles unless NO_COLOR is set (https://no-color.org/)."""
    return os.environ.get("NO_COLOR", "").strip() == ""


def enable_ansi_if_windows() -> None:
    """Turn on virtual-terminal ANSI on Windows so scan/fix colors render in conhost."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        std_out = -11
        enable_vt = 0x0004
        handle = kernel32.GetStdHandle(std_out)
        mode = ctypes.c_uint()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | enable_vt)
    except Exception:
        pass


def _diff_line_width() -> int:
    try:
        return max(40, shutil.get_terminal_size(fallback=(80, 24)).columns)
    except Exception:
        return 80


def format_report(
    report: ScoreReport,
    findings: list[Finding],
    compose_path: str,
    *,
    color: bool = True,
) -> str:
    lines = [
        _style(tr("cli.report_title"), FG_CYAN, color=color, bold=True),
        tr("cli.report_path", path=compose_path),
        _format_overall_score(report.overall, color=color),
        "",
        tr("cli.axis_scores"),
    ]
    for axis in AXIS_DISPLAY_ORDER:
        score = report.axis_scores[axis]
        lines.append(f"- {tr(f'axis.{axis.value}')}: {_color_score(score, color=color)}")

    lines.extend(
        [
            tr(
                "cli.finding_counts",
                critical=report.finding_counts[Severity.CRITICAL],
                high=report.finding_counts[Severity.HIGH],
                medium=report.finding_counts[Severity.MEDIUM],
                low=report.finding_counts[Severity.LOW],
            ),
            "",
            tr("cli.findings_heading"),
        ]
    )

    if not findings:
        lines.append(tr("cli.no_findings"))
        return "\n".join(lines)

    by_service = _group_findings_by_service(findings)
    for index, (service_name, service_findings) in enumerate(by_service):
        if index > 0:
            lines.append(_findings_service_separator(color=color))
        lines.append(tr("cli.affected_service", service=service_name))
        for finding in service_findings:
            severity_label = _style(
                finding.severity.value.upper(),
                SEVERITY_COLORS[finding.severity],
                color=color,
                bold=True,
            )
            why_line = tr("cli.why_risky", text=finding.why_risky)
            fix_line = tr("cli.how_to_fix", text=finding.how_to_fix)
            lines.extend(
                [
                    f"- [{severity_label}] {finding.title}",
                    f"  {tr('cli.description', description=finding.description)}",
                    f"  {_style(why_line, FG_ORANGE, color=color, bold=True)}",
                    f"  {_style(fix_line, FG_GREEN, color=color, bold=True)}",
                ]
            )

    return "\n".join(lines)


def _group_findings_by_service(
    findings: list[Finding],
) -> list[tuple[str, list[Finding]]]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.affected_service].append(finding)
    for svc in grouped:
        grouped[svc].sort(
            key=lambda f: (SEVERITY_ORDER[f.severity], f.check_id),
        )
    return sorted(grouped.items(), key=lambda item: item[0])


def _findings_service_separator(*, color: bool) -> str:
    line = "-" * _diff_line_width()
    if not color:
        return line
    return f"{FG_GRAY}{line}{RESET}"


def code_section_separator_line(*, color: bool) -> str:
    """Full-width gray rule between prose and diff/code (same style as findings separators)."""
    return _findings_service_separator(color=color)


def _pad_line_for_full_width_highlight(line: str, width: int) -> str:
    if len(line) >= width:
        return line
    return line + (" " * (width - len(line)))


def strip_unified_diff_file_headers(diff: str) -> str:
    """Drop the --- / +++ path lines so the target path is not shown twice in the UI."""
    lines = diff.splitlines()
    if len(lines) >= 2 and lines[0].startswith("--- ") and lines[1].startswith("+++ "):
        return "\n".join(lines[2:])
    return diff


def format_unified_diff(diff: str, *, color: bool, line_width: int | None = None) -> str:
    """Highlight +/- diff lines as full-width dark rows (removed vs added)."""
    if not color or not diff.strip():
        return diff
    width = line_width if line_width is not None else _diff_line_width()
    out: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("+"):
            padded = _pad_line_for_full_width_highlight(line, width)
            out.append(f"{DIFF_BG_ADDED}{DIFF_FG_ADDED}{padded}{RESET}")
        elif line.startswith("---") or line.startswith("-"):
            padded = _pad_line_for_full_width_highlight(line, width)
            out.append(f"{DIFF_BG_REMOVED}{DIFF_FG_REMOVED}{padded}{RESET}")
        else:
            out.append(line)
    return "\n".join(out)


def _format_overall_score(score: int, *, color: bool) -> str:
    return tr("cli.overall_score", score=_color_score(score, color=color))


def _color_score(score: int, *, color: bool) -> str:
    color_code = FG_GREEN
    if score < 50:
        color_code = FG_RED
    elif score < 75:
        color_code = FG_YELLOW
    return _style(str(score), color_code, color=color, bold=True)


def _style(text: str, color_code: str, *, color: bool, bold: bool = False) -> str:
    if not color:
        return text
    prefix = ""
    if bold:
        prefix += BOLD
    prefix += color_code
    return f"{prefix}{text}{RESET}"
