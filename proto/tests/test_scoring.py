from __future__ import annotations

from hostveil.models import Axis, Finding, Severity
from hostveil.scoring import build_score_report


def _finding(axis: Axis, severity: Severity, check_id: str) -> Finding:
    return Finding(
        check_id=check_id,
        axis=axis,
        severity=severity,
        title="title",
        description="description",
        why_risky="why",
        how_to_fix="fix",
        affected_service="svc",
    )


def test_scoring_counts_findings_by_axis_and_severity() -> None:
    findings = [
        _finding(Axis.SENSITIVE_DATA, Severity.CRITICAL, "a"),
        _finding(Axis.UNNECESSARY_EXPOSURE, Severity.HIGH, "b"),
        _finding(Axis.UNNECESSARY_EXPOSURE, Severity.LOW, "c"),
    ]

    report = build_score_report(findings)

    assert report.axis_scores[Axis.SENSITIVE_DATA] == 25
    assert report.axis_scores[Axis.EXCESSIVE_PERMISSIONS] == 100
    assert report.axis_scores[Axis.UNNECESSARY_EXPOSURE] == 60
    assert report.axis_scores[Axis.UPDATE_RISK] == 100
    assert report.finding_counts[Severity.CRITICAL] == 1
    assert report.finding_counts[Severity.HIGH] == 1
    assert report.finding_counts[Severity.LOW] == 1


def test_single_critical_finding_visibly_tanks_overall_score() -> None:
    report = build_score_report([
        _finding(Axis.SENSITIVE_DATA, Severity.CRITICAL, "a")
    ])

    assert report.overall == 74
    assert report.overall < 80


def test_multiple_findings_cap_axis_scores_at_zero() -> None:
    report = build_score_report([
        _finding(Axis.EXCESSIVE_PERMISSIONS, Severity.CRITICAL, "a"),
        _finding(Axis.EXCESSIVE_PERMISSIONS, Severity.CRITICAL, "b"),
    ])

    assert report.axis_scores[Axis.EXCESSIVE_PERMISSIONS] == 0
