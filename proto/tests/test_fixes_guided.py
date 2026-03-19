from __future__ import annotations

from pathlib import Path

from hostveil.cli import main


FIXTURE = Path(__file__).parent / "fixtures" / "guided-fix.yml"


def test_guided_fix_patch_can_print_to_stdout(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["patch", str(compose_file), "--patch"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "--- " in captured.out
    assert "+# hostveil guided fix: replace privileged mode with a minimal capability set." in captured.out
    assert "+    cap_add:" in captured.out
    assert "-    privileged: true" in captured.out


def test_guided_fix_patch_writes_default_patch_file(tmp_path: Path, capsys) -> None:
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")

    exit_code = main(["patch", str(compose_file)])
    captured = capsys.readouterr()
    patch_file = tmp_path / "hostveil-fixes.patch"

    assert exit_code == 0
    assert patch_file.exists()
    assert "Guided patch written to" in captured.out
    assert "cap_add" in patch_file.read_text(encoding="utf-8")
