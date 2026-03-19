from __future__ import annotations

from pathlib import Path

from hostveil.parser import load_project
from hostveil.rules.updates import scan_update_risk


FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_update_risk_rules_detect_expected_findings() -> None:
    project = load_project(FIXTURES / "update-risk.yml", include_override=False)

    findings = scan_update_risk(project)

    assert [(finding.check_id, finding.affected_service) for finding in findings] == [
        ("updates.latest_tag", "latest"),
        ("updates.no_tag", "no_tag"),
        ("updates.major_only_tag", "major_only"),
    ]
    assert findings[0].severity.value == "high"
    assert findings[1].severity.value == "medium"
    assert findings[2].severity.value == "low"


def test_update_risk_rules_skip_pinned_images() -> None:
    project = load_project(FIXTURES / "update-risk.yml", include_override=False)

    findings = scan_update_risk(project)

    assert all(finding.affected_service != "pinned" for finding in findings)
