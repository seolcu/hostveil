from __future__ import annotations

from pathlib import Path

import pytest

from hostveil.parser import ComposeParseError, load_bundle, load_project


FIXTURES = Path(__file__).parent / "fixtures" / "parser"


def test_load_project_merges_override_values() -> None:
    project = load_project(FIXTURES / "docker-compose.yml")

    web = project.services["web"]
    app = project.services["app"]

    assert len(project.loaded_files) == 2
    assert web.image == "nginx"
    assert [port.raw for port in web.ports] == ["8080:80", "127.0.0.1:8443:443"]
    assert web.environment["APP_ENV"] == "production"
    assert web.environment["SHARED"] == "override"
    assert web.environment["DEBUG"] == "true"
    assert app.privileged is True
    assert app.cap_add == ("NET_ADMIN",)


def test_load_project_accepts_directory_path() -> None:
    project = load_project(FIXTURES)
    assert project.primary_file.name == "docker-compose.yml"


def test_load_bundle_preserves_primary_text() -> None:
    bundle = load_bundle(FIXTURES / "docker-compose.yml")
    assert "services:" in bundle.primary_text
    assert bundle.override_paths[0].name == "docker-compose.override.yml"


def test_load_project_reports_missing_path() -> None:
    with pytest.raises(ComposeParseError):
        load_project(FIXTURES / "missing.yml")


def test_load_project_reports_malformed_yaml(tmp_path: Path) -> None:
    broken = tmp_path / "docker-compose.yml"
    broken.write_text("services:\n  api: [\n", encoding="utf-8")

    with pytest.raises(ComposeParseError):
        load_project(broken)
