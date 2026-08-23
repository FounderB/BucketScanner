"""Scanner tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from bucket_scanner.chains import compose_chains
from bucket_scanner.checks import check_bucket, check_service_accounts
from bucket_scanner.cli import main
from bucket_scanner.config import load_config, write_default_config
from bucket_scanner.fixture import load_fixture
from bucket_scanner.models import Severity
from bucket_scanner.report.sarif import render_sarif
from bucket_scanner.scan import run_scan, should_fail

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_load_fixture():
    folder_id, buckets, keys = load_fixture(FIXTURE)
    assert folder_id.startswith("b1g")
    assert len(buckets) == 2
    assert len(keys) == 1


def test_fixture_finds_public_bucket():
    _, buckets, keys = load_fixture(FIXTURE)
    findings = check_bucket(buckets[0]) + check_service_accounts(keys)
    rules = {item.rule_id for item in findings}
    assert "acl/public-read" in rules
    assert "encryption/disabled" in rules
    assert "iam/stale-static-key" in rules


def test_silent_exfil_chain():
    _, buckets, keys = load_fixture(FIXTURE)
    findings = check_bucket(buckets[0]) + check_service_accounts(keys)
    chains = compose_chains(buckets[:1], findings)
    assert any(chain.chain_id == "chain/silent-exfil" for chain in chains)


def test_run_scan_fixture():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    assert report.summary.buckets_scanned == 2
    assert report.summary.critical >= 1
    assert report.summary.chains >= 1


def test_should_fail_on_high():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    assert should_fail(report, Severity.HIGH)


def test_sarif_output():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    sarif = render_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_cli_fixture_scan(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--fixture", str(FIXTURE), "--json", "-q"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["summary"]["critical"] >= 1


def test_cli_fixture_sarif(tmp_path: Path):
    runner = CliRunner()
    sarif_path = tmp_path / "out.sarif"
    result = runner.invoke(
        main,
        ["scan", "--fixture", str(FIXTURE), "--sarif", str(sarif_path), "-q"],
    )
    assert result.exit_code == 1
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert data["runs"]


def test_cli_explain():
    runner = CliRunner()
    result = runner.invoke(main, ["explain", "acl/public-read"])
    assert result.exit_code == 0
    assert "Public read ACL" in result.output


def test_cli_init(tmp_path: Path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(main, ["init"])
        assert result.exit_code == 0
        assert Path(".bucket-scanner.toml").exists()


def test_write_default_config_force(tmp_path: Path):
    target = tmp_path / ".bucket-scanner.toml"
    write_default_config(target)
    with pytest.raises(FileExistsError):
        write_default_config(target)
    write_default_config(target, force=True)
    assert "folder_id" in target.read_text(encoding="utf-8")
