"""Rule orchestration for the prototype."""

from __future__ import annotations

from .models import ComposeProject, Finding


def scan_project(project: ComposeProject) -> list[Finding]:
    del project
    return []
