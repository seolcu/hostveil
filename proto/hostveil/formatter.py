"""CLI report formatting."""

from __future__ import annotations

from .i18n import tr
from .models import Axis, Finding, ScoreReport, SEVERITY_ORDER, Severity


RESET = "\033[0m"
BOLD = "\033[1m"
FG_RED = "\033[31m"
FG_YELLOW = "\033[33m"
FG_GREEN = "\033[32m"
FG_ORANGE = "\033[38;5;208m"
FG_CYAN = "\033[36m"

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

    ordered_findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER[finding.severity],
            finding.affected_service,
            finding.check_id,
        ),
    )
    if not ordered_findings:
        lines.append(tr("cli.no_findings"))
        return "\n".join(lines)

    for finding in ordered_findings:
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
                f"  {tr('cli.affected_service', service=finding.affected_service)}",
                f"  {tr('cli.description', description=finding.description)}",
                f"  {_style(why_line, FG_ORANGE, color=color, bold=True)}",
                f"  {_style(fix_line, FG_GREEN, color=color, bold=True)}",
            ]
        )

    return "\n".join(lines)


def format_unified_diff(diff: str, *, color: bool) -> str:
    """Color unified diff lines: removals red, additions green."""
    if not color or not diff.strip():
        return diff
    out: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++") or line.startswith("+"):
            out.append(_style(line, FG_GREEN, color=True))
        elif line.startswith("---") or line.startswith("-"):
            out.append(_style(line, FG_RED, color=True))
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
