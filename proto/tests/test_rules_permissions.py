from __future__ import annotations

from pathlib import Path

from hostveil.parser import load_project
from hostveil.rules.permissions import scan_permission_risk


FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_permission_rules_detect_expected_findings() -> None:
    project = load_project(FIXTURES / "permissions-risk.yml", include_override=False)

    findings = scan_permission_risk(project)

    assert [(finding.check_id, finding.affected_service) for finding in findings] == [
        ("permissions.privileged", "privileged"),
        ("permissions.root_user", "root_user"),
        ("permissions.implicit_root", "implicit_root"),
        ("permissions.host_network", "hostnet"),
        ("permissions.sensitive_mount", "docker_socket"),
        ("permissions.sensitive_mount", "host_home"),
    ]
    severities = [finding.severity.value for finding in findings]
    assert severities == ["critical", "high", "medium", "high", "critical", "high"]


def test_permission_rules_skip_non_sensitive_relative_mounts() -> None:
    project = load_project(FIXTURES / "permissions-risk.yml", include_override=False)

    findings = scan_permission_risk(project)

    assert all(finding.affected_service != "safe" for finding in findings)
