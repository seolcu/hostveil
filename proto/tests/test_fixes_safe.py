from __future__ import annotations

from pathlib import Path

from hostveil.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "safe-fix.yml"


def test_safe_fix_dry_run_shows_diff_without_writing(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["fix", str(compose_file), "--dry-run", "--yes", "--no-color"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Dry run only; no files were changed." in captured.out
    assert "+    image: nginx:stable" in captured.out
    assert compose_file.read_text(encoding="utf-8") == FIXTURE.read_text(encoding="utf-8")


def test_safe_fix_apply_writes_backup_and_updates_compose(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["fix", str(compose_file), "--yes", "--no-color"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert (tmp_path / "docker-compose.yml.bak").exists()
    updated = compose_file.read_text(encoding="utf-8")
    assert "image: nginx:stable" in updated
    assert '127.0.0.1:8080:80' in updated
    assert "Applied fix: Pin web image from nginx to nginx:stable" in captured.out
    assert "Applied fix: Bind web port 8080:80 to 127.0.0.1" in captured.out
