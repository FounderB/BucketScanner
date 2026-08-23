"""CI profile configuration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from bucket_scanner.cli import main
from bucket_scanner.config import load_config
from bucket_scanner.scan import run_scan

CI_CONFIG = Path("examples/ci/.bucket-scanner.toml")


@pytest.mark.parametrize(
    "profile",
    [
        "yc-fixture",
        "aws-fixture",
        "stack-fixture",
        "azure-fixture",
        "gcs-fixture",
        "yc-prod-baseline",
        "aws-prod-baseline",
        "azure-prod-baseline",
        "gcs-prod-baseline",
    ],
)
def test_ci_profiles_load_and_scan(profile: str):
    app = load_config(CI_CONFIG)
    assert profile in app.profiles
    config = app.scan
    app.profiles[profile].apply_to(config)
    fixture = app.profiles[profile].fixture
    report = run_scan(
        folder_id=None,
        fixture=fixture,
        config=config,
        terraform_path=config.terraform_path,
        repo_path=config.repo_path,
        tracefuse_report=config.tracefuse_report,
    )
    assert report.summary.buckets_scanned >= 1
    assert report.method == "fixture"


def test_ci_stack_fixture_has_iac_findings():
    app = load_config(CI_CONFIG)
    config = app.scan
    profile = app.profiles["stack-fixture"]
    profile.apply_to(config)
    report = run_scan(
        folder_id=None,
        fixture=profile.fixture,
        config=config,
        terraform_path=profile.terraform_path,
        repo_path=profile.repo_path,
        tracefuse_report=profile.tracefuse_report,
    )
    rules = {item.rule_id for item in report.findings}
    assert any(rule.startswith("iac/") for rule in rules)


def test_ci_profile_cli_json():
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "scan",
            "--profile",
            "aws-fixture",
            "--config",
            str(CI_CONFIG),
            "--json",
            "-q",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["cloud"] == "aws"
    assert payload["method"] == "fixture"


def test_ci_baseline_profile_delta_gate():
    from bucket_scanner.gate import apply_gate

    app = load_config(CI_CONFIG)
    config = app.scan
    profile = app.profiles["yc-prod-baseline"]
    profile.apply_to(config)
    report = run_scan(folder_id=None, fixture=profile.fixture, config=config)
    report = apply_gate(
        report,
        suppressions=config.suppressions,
        baseline_path=config.baseline_path,
    )
    assert report.new_findings == []
    assert config.baseline_path == Path("baselines/yc-prod.json")
