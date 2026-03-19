from __future__ import annotations

from pathlib import Path

from hostveil.parser import load_project
from hostveil.rules.exposure import scan_exposure_risk


FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_exposure_rules_detect_expected_findings() -> None:
    project = load_project(FIXTURES / "exposure-risk.yml", include_override=False)

    findings = scan_exposure_risk(project)

    assert [(finding.check_id, finding.affected_service) for finding in findings] == [
        ("exposure.public_binding", "jellyfin"),
        ("exposure.public_binding", "adminer"),
        ("exposure.admin_interface_public", "adminer"),
        ("exposure.public_binding", "vaultwarden"),
        ("exposure.reverse_proxy_expected", "vaultwarden"),
    ]


def test_exposure_rules_skip_localhost_bindings() -> None:
    project = load_project(FIXTURES / "exposure-risk.yml", include_override=False)

    findings = scan_exposure_risk(project)

    assert all(finding.affected_service != "redis" for finding in findings)
