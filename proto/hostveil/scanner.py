"""Rule orchestration for the prototype."""

from __future__ import annotations

from .models import ComposeProject, Finding
from .rules import scan_update_risk


def scan_project(project: ComposeProject) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(scan_update_risk(project))
    return findings
