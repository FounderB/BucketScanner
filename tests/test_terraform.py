"""Terraform parser and diff tests."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.diff import diff_terraform
from bucket_scanner.fixture import load_fixture
from bucket_scanner.terraform import parse_terraform_file

TF = Path("examples/demo-vulnerable/terraform/main.tf")
TF_AWS = Path("examples/demo-vulnerable/terraform-aws/main.tf")
TF_AZURE = Path("examples/demo-vulnerable/terraform-azure/main.tf")
TF_GCS = Path("examples/demo-vulnerable/terraform-gcs/main.tf")
FIXTURE = Path("examples/demo-vulnerable/fixture.toml")
AWS_FIXTURE = Path("examples/demo-vulnerable/fixture-aws.toml")
AZURE_FIXTURE = Path("examples/demo-vulnerable/fixture-azure.toml")
GCS_FIXTURE = Path("examples/demo-vulnerable/fixture-gcs.toml")


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


def test_parse_aws_terraform_acl_refs():
    intents = parse_terraform_file(TF_AWS)
    by_bucket = {item.bucket: item for item in intents}
    assert by_bucket["prod-backups-open"].acl == "private"
    assert by_bucket["internal-logs-secure"].acl == "private"


def test_diff_aws_acl_drift():
    _, buckets, _ = load_fixture(AWS_FIXTURE)
    findings = diff_terraform(TF_AWS.parent, buckets)
    rules = {item.rule_id for item in findings}
    assert "iac/acl-drift" in rules
    assert "iac/bpa-drift" in rules
    assert "iac/ghost-bucket" in rules


def test_parse_aws_bpa_intent():
    intents = parse_terraform_file(TF_AWS)
    by_bucket = {item.bucket: item for item in intents}
    bpa = by_bucket["prod-backups-open"].block_public_access
    assert bpa["BlockPublicAcls"] is True
    assert bpa["RestrictPublicBuckets"] is True


def test_parse_azure_terraform_containers():
    intents = parse_terraform_file(TF_AZURE)
    by_bucket = {item.bucket: item for item in intents}
    assert by_bucket["prod-backups-open"].container_access_type == "private"
    assert by_bucket["internal-logs-secure"].acl == "private"


def test_diff_azure_container_drift():
    _, buckets, _ = load_fixture(AZURE_FIXTURE)
    findings = diff_terraform(TF_AZURE.parent, buckets)
    rules = {item.rule_id for item in findings}
    assert "iac/container-access-drift" in rules
    assert "iac/ghost-bucket" in rules


def test_parse_gcs_terraform_buckets():
    intents = parse_terraform_file(TF_GCS)
    by_bucket = {item.bucket: item for item in intents}
    assert by_bucket["prod-backups-open"].public_access_prevention == "enforced"
    assert by_bucket["prod-backups-open"].uniform_bucket_level_access is True


def test_diff_gcs_pap_and_ubla_drift():
    _, buckets, _ = load_fixture(GCS_FIXTURE)
    findings = diff_terraform(TF_GCS.parent, buckets)
    rules = {item.rule_id for item in findings}
    assert "iac/pap-drift" in rules
    assert "iac/ubla-drift" in rules
    assert "iac/iam-public-drift" in rules
    assert "iac/acl-drift" in rules
