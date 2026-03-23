from __future__ import annotations

from pathlib import Path

from hostveil.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "guided-fix.yml"


def test_fix_preview_shows_guided_diff_without_writing(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["fix", str(compose_file), "--preview-changes", "--yes"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Fix file:" in captured.out
    assert "+# hostveil guided fix: replace privileged mode with a minimal capability set." in captured.out
    assert "+    cap_add:" in captured.out
    assert "-    privileged: true" in captured.out
    assert "Preview only; no files were changed." in captured.out
    assert compose_file.read_text(encoding="utf-8") == FIXTURE.read_text(encoding="utf-8")


def test_fix_apply_updates_compose_and_creates_backup(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["fix", str(compose_file), "--yes"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert (tmp_path / "docker-compose.yml.bak").exists()
    updated = compose_file.read_text(encoding="utf-8")
    assert "privileged: true" not in updated
    assert "cap_add:" in updated
    assert "Applied review-required privileged-container updates." in captured.out
