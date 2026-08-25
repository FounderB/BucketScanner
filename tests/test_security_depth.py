"""Security depth unit tests (BPA missing, chains, object lock)."""

from __future__ import annotations

from bucket_scanner.chains import PUBLIC_RULES, compose_chains
from bucket_scanner.checks import (
    PROD_LIKE,
    check_bucket,
    dedupe_account_scoped_findings,
)
from bucket_scanner.models import BucketSnapshot, Finding, Severity


def test_aws_missing_bpa_is_high():
    bucket = BucketSnapshot(
        name="data",
        cloud="aws",
        folder_id="123456789012",
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


def test_account_bpa_access_denied_is_unknown_not_missing():
    bucket = BucketSnapshot(
        name="data",
        cloud="aws",
        folder_id="123456789012",
        metadata_known=True,
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        block_public_access={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
        account_public_access_block=None,
        partial_metadata=["account_public_access"],
    )
    findings = check_bucket(bucket)
    ids = {f.rule_id for f in findings}
    assert "aws/account-public-access-unknown" in ids
    assert "aws/account-public-access-missing" not in ids


def test_bucket_bpa_partial_still_checks_account():
    bucket = BucketSnapshot(
        name="data",
        cloud="aws",
        folder_id="123456789012",
        metadata_known=True,
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        block_public_access=None,
        account_public_access_block={},
        partial_metadata=["block_public_access"],
    )
    findings = check_bucket(bucket)
    ids = {f.rule_id for f in findings}
    assert "aws/block-public-access-missing" not in ids
    assert "aws/account-public-access-missing" in ids


def test_dedupe_account_scoped_findings():
    findings = [
        Finding(
            rule_id="aws/account-public-access-missing",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="a",
            evidence={"account_id": "111"},
        ),
        Finding(
            rule_id="aws/account-public-access-missing",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="b",
            evidence={"account_id": "111"},
        ),
        Finding(
            rule_id="aws/block-public-access-missing",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="a",
        ),
    ]
    out = dedupe_account_scoped_findings(findings)
    assert len(out) == 2
    assert sum(1 for f in out if f.rule_id.startswith("aws/account")) == 1


def test_hardening_gaps_are_not_public_rules():
    assert "aws/block-public-access-missing" not in PUBLIC_RULES
    assert "aws/account-public-access-missing" not in PUBLIC_RULES
    assert "azure/account-public-access-enabled" not in PUBLIC_RULES
    assert "azure/container-public-access" in PUBLIC_RULES


def test_missing_bpa_does_not_feed_silent_exfil():
    bucket = BucketSnapshot(
        name="private",
        cloud="aws",
        metadata_known=True,
        logging_enabled=False,
        versioning_enabled=False,
    )
    findings = [
        Finding(
            rule_id="aws/block-public-access-missing",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="private",
        ),
        Finding(
            rule_id="logging/disabled",
            title="t",
            severity=Severity.MEDIUM,
            message="m",
            bucket="private",
        ),
        Finding(
            rule_id="versioning/disabled",
            title="t",
            severity=Severity.MEDIUM,
            message="m",
            bucket="private",
        ),
    ]
    chains = compose_chains([bucket], findings)
    assert not any(c.chain_id == "chain/silent-exfil" for c in chains)


def test_prod_like_does_not_match_product():
    assert not PROD_LIKE.search("product-assets")
    assert PROD_LIKE.search("prod-backup")
    assert PROD_LIKE.search("my-production-data")


def test_azure_skips_synthetic_acl_public_finding():
    bucket = BucketSnapshot(
        name="leak",
        cloud="azure",
        acl="public-read",
        metadata_known=True,
        encryption_enabled=True,
        logging_enabled=True,
        versioning_enabled=True,
        block_public_access={"public_access": "container"},
        account_public_access_block={"allow_blob_public_access": False},
        tags={"storage_account": "acct"},
    )
    findings = check_bucket(bucket)
    ids = {f.rule_id for f in findings}
    assert "azure/container-public-access" in ids
    assert "acl/public-read" not in ids


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
