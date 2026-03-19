"""Rule orchestration for the prototype."""

from __future__ import annotations

from .models import ComposeProject, Finding
from .rules import scan_exposure_risk, scan_permission_risk, scan_update_risk


def scan_project(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_exposure_risk(project))
    findings.extend(scan_permission_risk(project))
    findings.extend(scan_update_risk(project))
    return findings
