"""Smoke tests for Bucket Scanner CLI."""

from click.testing import CliRunner

from bucket_scanner.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Object Storage security scanner" in result.output


def test_cli_list_fixture():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["list", "--fixture", "examples/demo-vulnerable/fixture.toml"],
    )
    assert result.exit_code == 0
    assert "prod-backups-open" in result.output
