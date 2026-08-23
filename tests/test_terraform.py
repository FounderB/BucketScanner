"""Terraform parser and diff tests."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.diff import diff_terraform
from bucket_scanner.fixture import load_fixture
from bucket_scanner.terraform import parse_terraform_file

TF = Path("examples/demo-vulnerable/terraform/main.tf")
FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_parse_terraform_file():
    intents = parse_terraform_file(TF)
    names = {item.bucket for item in intents}
    assert "prod-backups-open" in names
    assert "internal-logs-secure" in names
    assert "terraform-only-never-created" in names


def test_diff_finds_acl_drift():
    _, buckets, _ = load_fixture(FIXTURE)
    findings = diff_terraform(TF.parent, buckets)
    rules = {item.rule_id for item in findings}
    assert "iac/acl-drift" in rules
    assert "iac/ghost-bucket" in rules


def test_diff_shadow_bucket_when_live_extra():
    from bucket_scanner.models import BucketSnapshot

    buckets = [
        BucketSnapshot(name="declared-in-tf", acl="private", metadata_known=True),
        BucketSnapshot(name="shadow-live-only", acl="private", metadata_known=True),
    ]
    tf = Path("tests/fixtures/terraform/minimal/main.tf")
    findings = diff_terraform(tf.parent, buckets)
    rules = {item.rule_id for item in findings}
    assert "iac/shadow-bucket" in rules
