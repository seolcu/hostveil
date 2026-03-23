"""CLI report formatting."""

from __future__ import annotations

import os
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

FINDINGS_SERVICE_SEPARATOR_WIDTH = 50
# Unified diff: full-line background (high-contrast foreground on each)
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
FG_ON_DIFF_RED = "\033[97m"
FG_ON_DIFF_GREEN = "\033[30m"

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
    line = "-" * FINDINGS_SERVICE_SEPARATOR_WIDTH
    if not color:
        return line
    return f"{FG_GRAY}{line}{RESET}"


def format_unified_diff(diff: str, *, color: bool) -> str:
    """Highlight unified diff lines with background color (red = removed, green = added)."""
    if not color or not diff.strip():
        return diff
    out: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("+"):
            out.append(f"{BG_GREEN}{FG_ON_DIFF_GREEN}{line}{RESET}")
        elif line.startswith("---") or line.startswith("-"):
            out.append(f"{BG_RED}{FG_ON_DIFF_RED}{line}{RESET}")
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
