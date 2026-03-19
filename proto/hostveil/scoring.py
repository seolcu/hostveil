"""Score aggregation for hostveil findings."""

from __future__ import annotations

from .models import Axis, Finding, ScoreReport, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 75,
    Severity.HIGH: 35,
    Severity.MEDIUM: 15,
    Severity.LOW: 5,
}

AXIS_WEIGHTS = {
    Axis.SENSITIVE_DATA: 0.35,
    Axis.EXCESSIVE_PERMISSIONS: 0.30,
    Axis.UNNECESSARY_EXPOSURE: 0.20,
    Axis.UPDATE_RISK: 0.15,
}


def build_score_report(findings: list[Finding]) -> ScoreReport:
    axis_penalties = {axis: 0 for axis in Axis}
    finding_counts = {severity: 0 for severity in Severity}

    for finding in findings:
        axis_penalties[finding.axis] += SEVERITY_WEIGHTS[finding.severity]
        finding_counts[finding.severity] += 1

    axis_scores = {
        axis: max(0, 100 - axis_penalties[axis])
        for axis in Axis
    }
    overall = round(
        sum(axis_scores[axis] * weight for axis, weight in AXIS_WEIGHTS.items())
    )
    return ScoreReport(
        overall=overall,
        axis_scores=axis_scores,
        finding_counts=finding_counts,
    )
