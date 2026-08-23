"""Security checks for bucket snapshots."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable

from bucket_scanner.models import BucketSnapshot, Finding, ServiceAccountKeySnapshot, Severity

PUBLIC_ACL_VALUES = {"public-read", "public-read-write", "public"}
PROD_LIKE = re.compile(r"(prod|backup|archive|payment|pii)", re.IGNORECASE)
RISKY_POLICY_NAMES = {
    "AdministratorAccess",
    "AmazonS3FullAccess",
    "PowerUserAccess",
    "IAMFullAccess",
}


def check_bucket(bucket: BucketSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    if not bucket.metadata_known:
        findings.append(
            Finding(
                rule_id="metadata/limited",
                title="Limited bucket metadata",
                severity=Severity.INFO,
                message=(
                    f"Bucket '{bucket.name}' was inventoried without S3 static keys — "
                    "ACL/encryption/logging checks skipped."
                ),
                bucket=bucket.name,
                evidence={"metadata_known": False},
                remediation=(
                    "Provide YC_ACCESS_KEY_ID and YC_SECRET_ACCESS_KEY for full metadata scan."
                ),
            )
        )
    else:
        findings.extend(_check_acl(bucket))
        findings.extend(_check_policy(bucket))
        findings.extend(_check_encryption(bucket))
        findings.extend(_check_logging(bucket))
        findings.extend(_check_versioning(bucket))
        findings.extend(_check_lifecycle(bucket))
        findings.extend(_check_tags(bucket))
        findings.extend(_check_block_public_access(bucket))
    findings.extend(_check_probe(bucket))
    return findings


def check_service_accounts(
    keys: Iterable[ServiceAccountKeySnapshot],
    *,
    key_age_days: int = 90,
) -> list[Finding]:
    findings: list[Finding] = []
    for key in keys:
        if key.age_days is not None and key.age_days > key_age_days:
            findings.append(
                Finding(
                    rule_id="iam/stale-static-key",
                    title="Stale service account static key",
                    severity=Severity.HIGH,
                    message=(
                        f"Service account key for {key.sa_id} is {key.age_days} days old "
                        f"(policy threshold: {key_age_days} days)."
                    ),
                    resource=key.sa_id,
                    evidence={"age_days": key.age_days, "key_id": key.key_id},
                    remediation="Rotate static keys regularly and prefer short-lived IAM tokens.",
                )
            )
        if _is_over_privileged(key.roles):
            is_storage_admin = any(
                role.endswith("storage.admin") or role == "storage.admin" for role in key.roles
            )
            message = (
                f"Service account {key.sa_id} has broad storage.admin access."
                if is_storage_admin
                else f"IAM principal {key.sa_id} has risky S3 or admin policies attached."
            )
            findings.append(
                Finding(
                    rule_id="iam/over-privileged-sa",
                    title="Over-privileged storage principal",
                    severity=Severity.HIGH,
                    message=message,
                    resource=key.sa_id,
                    evidence={"roles": key.roles},
                    remediation="Grant storage.viewer/editor scoped to required buckets only.",
                )
            )
    return findings


def _is_over_privileged(roles: list[str]) -> bool:
    for role in roles:
        if role.endswith("storage.admin") or role == "storage.admin":
            return True
        if role in RISKY_POLICY_NAMES:
            return True
        if role.startswith("inline:") and any(
            marker in role.lower() for marker in ("admin", "s3full", "fullaccess")
        ):
            return True
    return False


def _check_acl(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.acl not in PUBLIC_ACL_VALUES:
        return []
    rule_id = (
        "acl/public-read-write" if bucket.acl == "public-read-write" else "acl/public-read"
    )
    return [
        Finding(
            rule_id=rule_id,
            title="Bucket ACL allows anonymous access",
            severity=Severity.CRITICAL,
            message=f"Bucket '{bucket.name}' ACL is '{bucket.acl}'.",
            bucket=bucket.name,
            evidence={"acl": bucket.acl},
            remediation="Set bucket ACL to private and use signed URLs or IAM policies.",
        )
    ]


def _check_policy(bucket: BucketSnapshot) -> list[Finding]:
    if not bucket.policy:
        return []
    statements = bucket.policy.get("Statement", [])
    for statement in statements:
        principal = statement.get("Principal", {})
        effect = statement.get("Effect")
        if effect != "Allow":
            continue
        if principal == "*" or principal.get("AWS") == "*":
            return [
                Finding(
                    rule_id="policy/overly-permissive",
                    title="Bucket policy allows any principal",
                    severity=Severity.HIGH,
                    message=f"Bucket '{bucket.name}' policy contains Principal='*'.",
                    bucket=bucket.name,
                    evidence={"statement": statement},
                    remediation="Restrict Principal to specific accounts, roles, or users.",
                )
            ]
    return []


def _check_encryption(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.encryption_enabled:
        return []
    return [
        Finding(
            rule_id="encryption/disabled",
            title="Default encryption disabled",
            severity=Severity.HIGH,
            message=f"Bucket '{bucket.name}' has no default server-side encryption.",
            bucket=bucket.name,
            evidence={"encryption_enabled": False},
            remediation="Enable default server-side encryption (SSE-S3 or SSE-KMS).",
        )
    ]


def _check_logging(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.logging_enabled:
        return []
    return [
        Finding(
            rule_id="logging/disabled",
            title="Access logging disabled",
            severity=Severity.MEDIUM,
            message=f"Bucket '{bucket.name}' does not ship access logs.",
            bucket=bucket.name,
            evidence={"logging_enabled": False},
            remediation="Enable access logging to a dedicated audit bucket.",
        )
    ]


def _check_versioning(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.versioning_enabled:
        return []
    return [
        Finding(
            rule_id="versioning/disabled",
            title="Object versioning disabled",
            severity=Severity.MEDIUM,
            message=f"Bucket '{bucket.name}' has versioning disabled.",
            bucket=bucket.name,
            evidence={"versioning_enabled": False},
            remediation="Enable versioning on production and backup buckets.",
        )
    ]


def _check_lifecycle(bucket: BucketSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for rule in bucket.lifecycle_rules:
        expiration = rule.get("Expiration", {})
        days = expiration.get("Days")
        if days is not None and days <= 7:
            findings.append(
                Finding(
                    rule_id="lifecycle/aggressive-expiration",
                    title="Aggressive lifecycle expiration",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Bucket '{bucket.name}' expires objects after {days} days "
                        f"(rule id={rule.get('ID', 'unknown')})."
                    ),
                    bucket=bucket.name,
                    evidence={"days": days, "rule": rule},
                    remediation="Review retention requirements before applying short expiration.",
                )
            )
    return findings


def _check_tags(bucket: BucketSnapshot) -> list[Finding]:
    if not PROD_LIKE.search(bucket.name):
        return []
    env = bucket.tags.get("environment") or bucket.tags.get("env")
    if env:
        return []
    return [
        Finding(
            rule_id="tags/missing-env",
            title="Production-like bucket missing environment tag",
            severity=Severity.LOW,
            message=(
                f"Bucket '{bucket.name}' looks production-like but has no environment/env tag."
            ),
            bucket=bucket.name,
            evidence={"tags": bucket.tags},
            remediation="Tag buckets with environment, owner, and data classification.",
        )
    ]


def _check_block_public_access(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "aws":
        return []
    findings: list[Finding] = []
    config = bucket.block_public_access or {}
    if config and not all(
        config.get(key, False)
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    ):
        findings.append(
            Finding(
                rule_id="aws/block-public-access-incomplete",
                title="S3 Block Public Access incomplete",
                severity=Severity.HIGH,
                message=(
                    f"Bucket '{bucket.name}' does not enforce all Block Public Access settings."
                ),
                bucket=bucket.name,
                evidence={"block_public_access": config},
                remediation="Enable all four Block Public Access settings on the bucket.",
            )
        )
    account = bucket.account_public_access_block or {}
    if account and not all(
        account.get(key, False)
        for key in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    ):
        findings.append(
            Finding(
                rule_id="aws/account-public-access-incomplete",
                title="Account-level Block Public Access incomplete",
                severity=Severity.HIGH,
                message="AWS account does not enforce full Block Public Access.",
                bucket=bucket.name,
                evidence={"account_public_access_block": account},
                remediation=(
                    "Enable account-level S3 Block Public Access in AWS console or org policy."
                ),
            )
        )
    return findings


def _check_probe(bucket: BucketSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    if bucket.anonymous_listable:
        findings.append(
            Finding(
                rule_id="probe/anonymous-list",
                title="Anonymous bucket listing confirmed",
                severity=Severity.CRITICAL,
                message=f"Bucket '{bucket.name}' allows anonymous ListObjects.",
                bucket=bucket.name,
                evidence={"anonymous_listable": True},
                remediation="Remove public ACL/policy and verify with --probe after fix.",
            )
        )
    elif bucket.anonymous_readable and bucket.acl == "private":
        findings.append(
            Finding(
                rule_id="probe/anonymous-read-confirmed",
                title="Anonymous read confirmed despite private ACL",
                severity=Severity.CRITICAL,
                message=(
                    f"Bucket '{bucket.name}' is reachable anonymously while ACL says private."
                ),
                bucket=bucket.name,
                evidence={"anonymous_readable": True, "acl": bucket.acl},
                remediation="Declared vs real mismatch — inspect bucket policy and CDN origin.",
            )
        )
    return findings


def apply_overrides(findings: list[Finding], overrides: dict[str, Severity]) -> list[Finding]:
    updated: list[Finding] = []
    for finding in findings:
        if finding.rule_id in overrides:
            updated.append(finding.model_copy(update={"severity": overrides[finding.rule_id]}))
        else:
            updated.append(finding)
    return updated


def redact_finding(finding: Finding) -> Finding:
    evidence = json.loads(json.dumps(finding.evidence))
    return finding.model_copy(update={"evidence": _redact_obj(evidence)})


def _redact_obj(value):
    if isinstance(value, dict):
        return {key: _redact_obj(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_obj(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if len(value) > 8 and any(
            marker in lowered for marker in ("key", "token", "secret", "password")
        ):
            return value[:4] + "…" + value[-2:]
    return value
