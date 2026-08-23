"""Checks, probe, redaction, and config tests."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.checks import (
    apply_overrides,
    check_bucket,
    check_service_accounts,
    redact_finding,
)
from bucket_scanner.config import load_config
from bucket_scanner.models import BucketSnapshot, Finding, ServiceAccountKeySnapshot, Severity
from bucket_scanner.probe import probe_bucket
from bucket_scanner.scan import run_scan, should_fail

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_metadata_unknown_skips_encryption_check():
    bucket = BucketSnapshot(name="x", metadata_known=False)
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "encryption/disabled" not in rules
    assert "metadata/limited" in rules


def test_tags_missing_env_on_prod_like_name():
    bucket = BucketSnapshot(
        name="prod-backups-east",
        acl="private",
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        metadata_known=True,
        tags={},
    )
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "tags/missing-env" in rules


def test_tags_present_env_no_finding():
    bucket = BucketSnapshot(
        name="prod-backups-east",
        acl="private",
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        metadata_known=True,
        tags={"environment": "prod"},
    )
    rules = {item.rule_id for item in check_bucket(bucket)}
    assert "tags/missing-env" not in rules


def test_redact_finding_masks_secrets():
    finding = Finding(
        rule_id="iam/stale-static-key",
        title="t",
        severity=Severity.HIGH,
        message="m",
        evidence={"key_id": "YCAJdeadbeefsecretkey"},
    )
    redacted = redact_finding(finding)
    assert "deadbeef" not in str(redacted.evidence["key_id"])


def test_apply_overrides():
    finding = Finding(
        rule_id="versioning/disabled",
        title="t",
        severity=Severity.MEDIUM,
        message="m",
    )
    updated = apply_overrides([finding], {"versioning/disabled": Severity.LOW})
    assert updated[0].severity == Severity.LOW


def test_key_age_threshold():
    keys = [ServiceAccountKeySnapshot(sa_id="sa1", age_days=50, roles=[])]
    assert not check_service_accounts(keys, key_age_days=90)
    keys = [ServiceAccountKeySnapshot(sa_id="sa1", age_days=120, roles=[])]
    assert check_service_accounts(keys, key_age_days=90)


def test_ignore_buckets_config(tmp_path: Path):
    config_text = """
[scan]
folder_id = "b1gTEST"

[scan.ignore_buckets]
names = ["skip-me"]
"""
    cfg_path = tmp_path / ".bucket-scanner.toml"
    cfg_path.write_text(config_text, encoding="utf-8")
    cfg = load_config(cfg_path).scan
    assert "skip-me" in cfg.ignore_buckets


def test_probe_detects_public_listing(monkeypatch):
    class FakeResponse:
        status_code = 200
        text = '<?xml version="1.0"?><ListBucketResult/>'

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def head(self, url):
            response = FakeResponse()
            response.status_code = 403
            return response

        def get(self, url):
            return FakeResponse()

    monkeypatch.setattr("bucket_scanner.probe.httpx.Client", FakeClient)
    bucket = BucketSnapshot(name="open", acl="private", metadata_known=True)
    probed = probe_bucket(bucket)
    rules = {item.rule_id for item in check_bucket(probed)}
    assert "probe/anonymous-list" in rules


def test_scan_with_terraform_fixture():
    report = run_scan(
        folder_id=None,
        fixture=FIXTURE,
        config=load_config().scan,
        terraform_path=Path("examples/demo-vulnerable/terraform"),
    )
    rules = {item.rule_id for item in report.findings}
    assert "iac/acl-drift" in rules
    assert should_fail(report, Severity.HIGH)


def test_should_not_fail_on_critical_when_threshold_critical_only():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    assert should_fail(report, Severity.CRITICAL)
    low_only = [Finding(rule_id="x", title="t", severity=Severity.LOW, message="m")]

    low_report = report.model_copy(update={"findings": low_only, "chains": []})
    assert not should_fail(low_report, Severity.HIGH)
