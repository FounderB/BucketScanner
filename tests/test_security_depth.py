"""Security depth unit tests (BPA missing, chains, object lock)."""

from __future__ import annotations

from bucket_scanner.chains import compose_chains
from bucket_scanner.checks import check_bucket
from bucket_scanner.models import BucketSnapshot, Finding, Severity


def test_aws_missing_bpa_is_high():
    bucket = BucketSnapshot(
        name="data",
        cloud="aws",
        metadata_known=True,
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        block_public_access=None,
        account_public_access_block=None,
    )
    findings = check_bucket(bucket)
    ids = {f.rule_id for f in findings}
    assert "aws/block-public-access-missing" in ids
    assert "aws/account-public-access-missing" in ids
    assert all(
        f.severity == Severity.HIGH for f in findings if f.rule_id.endswith("public-access-missing")
    )


def test_privileged_public_blast_chain():
    bucket = BucketSnapshot(name="public-prod", cloud="yandex", metadata_known=True)
    findings = [
        Finding(
            rule_id="acl/public-read",
            title="t",
            severity=Severity.CRITICAL,
            message="m",
            bucket="public-prod",
        ),
        Finding(
            rule_id="iam/over-privileged-sa",
            title="t",
            severity=Severity.HIGH,
            message="m",
            resource="ajeservice",
        ),
    ]
    chains = compose_chains([bucket], findings)
    assert any(c.chain_id == "chain/privileged-public-blast" for c in chains)


def test_azure_public_feeds_silent_exfil_chain():
    bucket = BucketSnapshot(
        name="leak",
        cloud="azure",
        metadata_known=True,
        logging_enabled=False,
        versioning_enabled=False,
    )
    findings = [
        Finding(
            rule_id="azure/container-public-access",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="leak",
        ),
        Finding(
            rule_id="logging/disabled",
            title="t",
            severity=Severity.MEDIUM,
            message="m",
            bucket="leak",
        ),
        Finding(
            rule_id="versioning/disabled",
            title="t",
            severity=Severity.MEDIUM,
            message="m",
            bucket="leak",
        ),
    ]
    chains = compose_chains([bucket], findings)
    assert any(c.chain_id == "chain/silent-exfil" for c in chains)


def test_object_lock_disabled_on_prod_like():
    bucket = BucketSnapshot(
        name="prod-backup",
        cloud="aws",
        metadata_known=True,
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        object_lock_enabled=False,
        block_public_access={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        account_public_access_block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    findings = check_bucket(bucket)
    assert any(f.rule_id == "object-lock/disabled" for f in findings)
