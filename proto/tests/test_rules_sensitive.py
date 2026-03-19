from __future__ import annotations

from pathlib import Path

from hostveil.parser import load_project
from hostveil.rules.sensitive import scan_sensitive_data


FIXTURES = Path(__file__).parent / "fixtures" / "rules" / "sensitive-risk"


def test_sensitive_rules_detect_expected_findings() -> None:
    project = load_project(FIXTURES, include_override=False)

    findings = scan_sensitive_data(project)

    assert [(finding.check_id, finding.affected_service) for finding in findings] == [
        ("sensitive.inline_secret", "inline_secret"),
        ("sensitive.default_credential", "default_credential"),
        ("sensitive.env_file_plaintext", "env_file_secret"),
    ]
    assert [finding.severity.value for finding in findings] == ["high", "critical", "high"]


def test_sensitive_rules_skip_interpolated_and_secret_file_values() -> None:
    project = load_project(FIXTURES, include_override=False)

    findings = scan_sensitive_data(project)

    assert all(finding.affected_service != "safe" for finding in findings)
