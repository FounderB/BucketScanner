"""Init preset tests."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from bucket_scanner.cli import main
from bucket_scanner.config import write_preset_config
from bucket_scanner.presets import PRESET_NAMES


def test_preset_names_non_empty():
    assert "yc-prod" in PRESET_NAMES
    assert "ci-offline" in PRESET_NAMES


def test_write_preset_config(tmp_path: Path):
    target = tmp_path / ".bucket-scanner.toml"
    write_preset_config(target, "yc-prod")
    text = target.read_text(encoding="utf-8")
    assert "yc-prod" in text
    assert "folder_ids" in text


def test_cli_init_preset():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, ["init", "--preset", "audit-only"])
        assert result.exit_code == 0
        assert Path(".bucket-scanner.toml").is_file()
        assert "audit-only" in Path(".bucket-scanner.toml").read_text(encoding="utf-8")
