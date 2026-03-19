from __future__ import annotations

from pathlib import Path

from hostveil.cli import main
from hostveil.formatter import format_report
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
    assert "Overall score: 74/100" in output
    assert "Sensitive data exposure: 25" in output


def test_cli_scan_renders_summary_without_color(capsys) -> None:
    exit_code = main(["scan", str(FIXTURE), "--no-color"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "hostveil scan report" in captured.out
    assert "Overall score:" in captured.out
    assert "Affected service: vaultwarden" in captured.out
    assert "[CRITICAL] Container runs in privileged mode" in captured.out
