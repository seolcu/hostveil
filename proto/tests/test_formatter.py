from __future__ import annotations

from pathlib import Path

from hostveil.cli import build_parser, main
from hostveil.formatter import format_report, format_unified_diff, should_use_color
from hostveil.models import Axis, Finding, ScoreReport, Severity


FIXTURE = Path(__file__).parent / "fixtures" / "report-scan.yml"


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
    assert output.index("[CRITICAL] Privileged") < output.index("[HIGH] Inline secret")
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


def test_format_unified_diff_colors_add_and_remove_lines() -> None:
    diff = "--- a.yml\n+++ b.yml\n@@ -1 +1 @@\n-old\n+new"
    out = format_unified_diff(diff, color=True)
    assert "\u001b[1m\u001b[31m--- a.yml\u001b[0m" in out
    assert "\u001b[1m\u001b[32m+++ b.yml\u001b[0m" in out
    assert "\u001b[1m\u001b[31m-old\u001b[0m" in out
    assert "\u001b[1m\u001b[32m+new\u001b[0m" in out
    plain = format_unified_diff(diff, color=False)
    assert plain == diff


def test_should_use_color_respects_cli_and_no_color_env(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert should_use_color(no_color_cli_flag=False) is True
    assert should_use_color(no_color_cli_flag=True) is False
    monkeypatch.setenv("NO_COLOR", "")
    assert should_use_color(no_color_cli_flag=False) is False
    monkeypatch.setenv("NO_COLOR", "1")
    assert should_use_color(no_color_cli_flag=False) is False


def test_cli_help_describes_fix_command_split() -> None:
    help_output = build_parser().format_help()

    assert "quick-fix" in help_output
    assert "Apply only safe, low-risk fixes." in help_output
    assert "fix" in help_output
    assert "Apply every available fix" in help_output
    assert "review-required" in help_output


def test_cli_scan_renders_summary_without_color(capsys) -> None:
    exit_code = main(["scan", str(FIXTURE), "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "hostveil scan report" in captured.out
    assert "Overall safety score:" in captured.out
    assert "Affected service: vaultwarden" in captured.out
    assert "[CRITICAL] Container runs in privileged mode" in captured.out
