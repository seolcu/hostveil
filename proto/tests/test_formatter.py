from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from hostveil.cli import build_parser, main
from hostveil.formatter import (
    format_report,
    format_unified_diff,
    should_use_color,
    strip_unified_diff_file_headers,
)
from hostveil.models import Axis, Finding, ScoreReport, Severity


FIXTURE = Path(__file__).parent / "fixtures" / "report-scan.yml"

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[@-~]")


def _strip_ansi(s: str) -> str:
    return _ANSI_ESCAPE.sub("", s)


def test_format_report_sorts_findings_and_supports_plain_output() -> None:
    report = ScoreReport(
        overall=74,
        axis_scores={
            Axis.SENSITIVE_DATA: 25,
            Axis.EXCESSIVE_PERMISSIONS: 100,
            Axis.UNNECESSARY_EXPOSURE: 100,
            Axis.UPDATE_RISK: 100,
        },
        finding_counts={
            Severity.CRITICAL: 1,
            Severity.HIGH: 1,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        },
    )
    findings = [
        Finding(
            check_id="medium",
            axis=Axis.SENSITIVE_DATA,
            severity=Severity.HIGH,
            title="Inline secret",
            description="desc",
            why_risky="why",
            how_to_fix="fix",
            affected_service="svc",
        ),
        Finding(
            check_id="critical",
            axis=Axis.EXCESSIVE_PERMISSIONS,
            severity=Severity.CRITICAL,
            title="Privileged",
            description="desc",
            why_risky="why",
            how_to_fix="fix",
            affected_service="svc",
        ),
    ]

    output = format_report(report, findings, "docker-compose.yml", color=False)

    assert "\u001b[" not in output
    assert output.index("Affected service: svc") < output.index("[CRITICAL] Privileged")
    assert output.index("[CRITICAL] Privileged") < output.index("[HIGH] Inline secret")
    assert output.count("Affected service: svc") == 1
    assert "Overall safety score: 74/100 (100 = safest)" in output
    assert "Sensitive data exposure: 25" in output


def test_format_report_colors_why_risky_and_how_to_fix() -> None:
    report = ScoreReport(
        overall=100,
        axis_scores={
            Axis.SENSITIVE_DATA: 100,
            Axis.EXCESSIVE_PERMISSIONS: 100,
            Axis.UNNECESSARY_EXPOSURE: 100,
            Axis.UPDATE_RISK: 100,
        },
        finding_counts={
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        },
    )
    findings = [
        Finding(
            check_id="x",
            axis=Axis.SENSITIVE_DATA,
            severity=Severity.HIGH,
            title="T",
            description="d",
            why_risky="because",
            how_to_fix="do this",
            affected_service="svc",
        ),
    ]
    output = format_report(report, findings, "c.yml", color=True)
    assert "\u001b[38;5;208m" in output
    assert "\u001b[1m\u001b[32mHow to fix:" in output
    assert "Why risky: because" in output
    assert "How to fix: do this" in output


def test_format_report_groups_findings_by_service_with_separator(monkeypatch) -> None:
    report = ScoreReport(
        overall=50,
        axis_scores={
            Axis.SENSITIVE_DATA: 100,
            Axis.EXCESSIVE_PERMISSIONS: 100,
            Axis.UNNECESSARY_EXPOSURE: 100,
            Axis.UPDATE_RISK: 100,
        },
        finding_counts={
            Severity.CRITICAL: 0,
            Severity.HIGH: 2,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        },
    )
    findings = [
        Finding(
            check_id="b",
            axis=Axis.EXCESSIVE_PERMISSIONS,
            severity=Severity.HIGH,
            title="B",
            description="db",
            why_risky="wb",
            how_to_fix="fb",
            affected_service="nginx",
        ),
        Finding(
            check_id="a",
            axis=Axis.SENSITIVE_DATA,
            severity=Severity.HIGH,
            title="A",
            description="da",
            why_risky="wa",
            how_to_fix="fa",
            affected_service="vaultwarden",
        ),
    ]
    monkeypatch.setattr(
        "hostveil.formatter.shutil.get_terminal_size",
        lambda _fallback=None: SimpleNamespace(columns=50, lines=24),
    )
    output = format_report(report, findings, "c.yml", color=False)

    nx = output.index("Affected service: nginx")
    vw = output.index("Affected service: vaultwarden")
    assert nx < vw
    sep = "\u2500" * 50
    assert nx < output.index(sep) < vw
    assert output.count("Affected service:") == 2


def test_strip_unified_diff_file_headers() -> None:
    raw = "--- a.yml\n+++ b.yml\n@@ -1 +1 @@\n-old\n+new"
    assert strip_unified_diff_file_headers(raw) == "@@ -1 +1 @@\n-old\n+new"
    assert strip_unified_diff_file_headers("@@ only\n") == "@@ only\n"


def test_format_unified_diff_colors_add_and_remove_lines() -> None:
    diff = "--- a.yml\n+++ b.yml\n@@ -1 +1 @@\n-old\n+new"
    width = 20
    out = format_unified_diff(diff, color=True, line_width=width)
    lines = out.splitlines()
    assert "\u001b[48;2;56;30;34m\u001b[38;2;252;236;238m" in lines[0]
    assert "\u001b[48;2;26;52;40m\u001b[38;2;220;248;228m" in lines[1]
    assert len(_strip_ansi(lines[0])) == width
    assert len(_strip_ansi(lines[1])) == width
    assert _strip_ansi(lines[2]) == "@@ -1 +1 @@"
    assert len(_strip_ansi(lines[3])) == width
    assert len(_strip_ansi(lines[4])) == width
    plain = format_unified_diff(diff, color=False)
    assert plain == diff


def test_should_use_color_respects_no_color_env(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_use_color() is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_use_color() is False


def test_cli_help_describes_fix_command_split() -> None:
    help_output = build_parser().format_help()

    assert "quick-fix" in help_output
    assert "Apply only safe, low-risk fixes." in help_output
    assert "fix" in help_output
    assert "Apply every available fix" in help_output
    assert "review-required" in help_output


def test_cli_scan_renders_summary(capsys, monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    exit_code = main(["scan", str(FIXTURE)])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "hostveil scan report" in captured.out
    assert "Overall safety score:" in captured.out
    assert "Affected service: vaultwarden" in captured.out
    assert "Container runs in privileged mode" in captured.out
