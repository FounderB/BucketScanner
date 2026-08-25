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
                    "Use an IAM token so the scanner can mint ephemeral S3 keys, "
                    "or provide YC_ACCESS_KEY_* for static keys. "
                    "Bucket.Get enrichment covers ACL/policy without S3 keys."
                ),
            )
        )
        findings.extend(_check_yc_anonymous_flags(bucket))
        findings.extend(_check_versioning(bucket))
        findings.extend(_check_yc_website(bucket))
        findings.extend(_check_yc_cors(bucket))
    else:
        findings.extend(_check_partial_metadata(bucket))
        findings.extend(_check_acl(bucket))
        findings.extend(_check_policy(bucket))
        findings.extend(_check_encryption(bucket))
        findings.extend(_check_logging(bucket))
        findings.extend(_check_versioning(bucket))
        findings.extend(_check_lifecycle(bucket))
        findings.extend(_check_tags(bucket))
        findings.extend(_check_block_public_access(bucket))
        findings.extend(_check_azure_public_access(bucket))
        findings.extend(_check_gcs_public_access(bucket))
        findings.extend(_check_yc_anonymous_flags(bucket))
        findings.extend(_check_yc_website(bucket))
        findings.extend(_check_yc_cors(bucket))
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
    rule_id = "acl/public-read-write" if bucket.acl == "public-read-write" else "acl/public-read"
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


def _principal_is_wildcard(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal == "*"
    if isinstance(principal, list):
        return any(_principal_is_wildcard(item) for item in principal)
    if isinstance(principal, dict):
        for value in principal.values():
            if _principal_is_wildcard(value):
                return True
    return False


def _check_policy(bucket: BucketSnapshot) -> list[Finding]:
    if not bucket.policy:
        return []
    if "policy" in bucket.partial_metadata:
        return []
    statements = bucket.policy.get("Statement", [])
    for statement in statements:
        principal = statement.get("Principal", {})
        effect = statement.get("Effect")
        if effect != "Allow":
            continue
        if _principal_is_wildcard(principal):
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
    if "encryption" in bucket.partial_metadata:
        return [
            Finding(
                rule_id="metadata/partial",
                title="Encryption metadata inaccessible",
                severity=Severity.MEDIUM,
                message=(
                    f"Could not read encryption settings for '{bucket.name}' "
                    "(AccessDenied or API error) — skipped encryption/disabled check."
                ),
                bucket=bucket.name,
                evidence={"partial": "encryption"},
                remediation="Grant the scanner SA permission to read bucket encryption config.",
            )
        ]
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
    if "logging" in bucket.partial_metadata:
        return []
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
    if "versioning" in bucket.partial_metadata:
        return []
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


def _check_azure_public_access(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "azure":
        return []
    findings: list[Finding] = []
    config = bucket.block_public_access or {}
    public_access = str(config.get("public_access", "off")).lower()
    if public_access in {"blob", "container"}:
        findings.append(
            Finding(
                rule_id="azure/container-public-access",
                title="Azure container allows anonymous blob access",
                severity=Severity.HIGH,
                message=(f"Container '{bucket.name}' public access is set to '{public_access}'."),
                bucket=bucket.name,
                evidence={"public_access": public_access},
                remediation=(
                    "Set container public access to private unless CDN requires blob access."
                ),
            )
        )
    account = bucket.account_public_access_block or {}
    if account.get("allow_blob_public_access") is True:
        findings.append(
            Finding(
                rule_id="azure/account-public-access-enabled",
                title="Storage account allows blob public access",
                severity=Severity.HIGH,
                message=(f"Storage account for '{bucket.name}' has allowBlobPublicAccess enabled."),
                bucket=bucket.name,
                evidence={"allow_blob_public_access": True},
                remediation="Disable allowBlobPublicAccess on the storage account unless required.",
            )
        )
    return findings


def _check_gcs_public_access(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "gcs":
        return []
    findings: list[Finding] = []
    config = bucket.block_public_access or {}
    if config.get("iam_public") is True:
        findings.append(
            Finding(
                rule_id="gcs/iam-public-principal",
                title="GCS bucket grants public IAM access",
                severity=Severity.HIGH,
                message=(
                    f"Bucket '{bucket.name}' allows allUsers or allAuthenticatedUsers in IAM."
                ),
                bucket=bucket.name,
                evidence={"iam_public": True},
                remediation="Remove public IAM bindings and enforce least-privilege roles.",
            )
        )
    pap = str(config.get("public_access_prevention", "unspecified")).lower()
    account = bucket.account_public_access_block or {}
    account_pap = str(account.get("public_access_prevention", pap)).lower()
    effective_pap = pap if pap not in {"", "unspecified"} else account_pap
    if effective_pap in {"inherited", "unspecified"}:
        findings.append(
            Finding(
                rule_id="gcs/public-access-prevention-not-enforced",
                title="GCS public access prevention not enforced",
                severity=Severity.HIGH,
                message=(f"Bucket '{bucket.name}' public access prevention is '{effective_pap}'."),
                bucket=bucket.name,
                evidence={"public_access_prevention": effective_pap},
                remediation="Set publicAccessPrevention=enforced on project or bucket.",
            )
        )
    if config.get("uniform_bucket_level_access") is False:
        findings.append(
            Finding(
                rule_id="gcs/uniform-access-disabled",
                title="GCS uniform bucket-level access disabled",
                severity=Severity.MEDIUM,
                message=(
                    f"Bucket '{bucket.name}' still allows legacy ACL-based public access paths."
                ),
                bucket=bucket.name,
                evidence={"uniform_bucket_level_access": False},
                remediation="Enable uniform bucket-level access and migrate ACLs to IAM.",
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
    elif bucket.anonymous_readable and bucket.acl in {None, "private", "unknown"}:
        findings.append(
            Finding(
                rule_id="probe/anonymous-read-confirmed",
                title="Anonymous read confirmed despite private ACL",
                severity=Severity.CRITICAL,
                message=(
                    f"Bucket '{bucket.name}' is reachable anonymously while ACL says "
                    f"'{bucket.acl or 'unknown'}'."
                ),
                bucket=bucket.name,
                evidence={"anonymous_readable": True, "acl": bucket.acl},
                remediation="Declared vs real mismatch — inspect bucket policy and CDN origin.",
            )
        )
    return findings


def _check_partial_metadata(bucket: BucketSnapshot) -> list[Finding]:
    if not bucket.partial_metadata:
        return []
    # encryption already emits metadata/partial; summarize other gaps once.
    other = [item for item in bucket.partial_metadata if item != "encryption"]
    if not other:
        return []
    return [
        Finding(
            rule_id="metadata/partial",
            title="Partial bucket metadata",
            severity=Severity.LOW,
            message=(f"Some APIs were denied for '{bucket.name}': {', '.join(sorted(other))}."),
            bucket=bucket.name,
            evidence={"partial_metadata": sorted(other)},
            remediation="Grant the scanner SA read access to ACL, policy, and logging APIs.",
        )
    ]


def _check_yc_anonymous_flags(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "yandex" or not bucket.anonymous_access_flags:
        return []
    flags = bucket.anonymous_access_flags
    findings: list[Finding] = []
    if flags.get("read"):
        findings.append(
            Finding(
                rule_id="yc/anonymous-read-enabled",
                title="Yandex anonymous read enabled",
                severity=Severity.CRITICAL,
                message=(
                    f"Bucket '{bucket.name}' has anonymousAccessFlags.read=true "
                    "(visible via Storage API without S3 keys)."
                ),
                bucket=bucket.name,
                evidence={"anonymous_access_flags": flags},
                remediation="Disable anonymous read in the Yandex console or Terraform.",
            )
        )
    if flags.get("list"):
        findings.append(
            Finding(
                rule_id="yc/anonymous-list-enabled",
                title="Yandex anonymous list enabled",
                severity=Severity.CRITICAL,
                message=(f"Bucket '{bucket.name}' has anonymousAccessFlags.list=true."),
                bucket=bucket.name,
                evidence={"anonymous_access_flags": flags},
                remediation="Disable anonymous list; prefer signed URLs for object access.",
            )
        )
    if flags.get("config_read"):
        findings.append(
            Finding(
                rule_id="yc/anonymous-config-read-enabled",
                title="Yandex anonymous config read enabled",
                severity=Severity.MEDIUM,
                message=(
                    f"Bucket '{bucket.name}' exposes configuration anonymously "
                    "(anonymousAccessFlags.configRead)."
                ),
                bucket=bucket.name,
                evidence={"anonymous_access_flags": flags},
                remediation="Disable configRead anonymous access flag.",
            )
        )
    return findings


def _check_yc_website(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "yandex" or not bucket.website_enabled:
        return []
    return [
        Finding(
            rule_id="yc/website-enabled",
            title="Yandex static website hosting enabled",
            severity=Severity.MEDIUM,
            message=(
                f"Bucket '{bucket.name}' has website hosting enabled — "
                "objects may be reachable via the website endpoint."
            ),
            bucket=bucket.name,
            evidence={"website_enabled": True},
            remediation=(
                "Disable website hosting unless the bucket is intentionally public static content; "
                "prefer CDN with signed origins for private assets."
            ),
        )
    ]


def _check_yc_cors(bucket: BucketSnapshot) -> list[Finding]:
    if bucket.cloud != "yandex" or not bucket.cors_rules:
        return []
    return [
        Finding(
            rule_id="yc/cors-enabled",
            title="Yandex CORS rules configured",
            severity=Severity.MEDIUM,
            message=(
                f"Bucket '{bucket.name}' has {len(bucket.cors_rules)} CORS rule(s) — "
                "overly broad AllowedOrigins can expose objects to browser exfiltration."
            ),
            bucket=bucket.name,
            evidence={"cors_rule_count": len(bucket.cors_rules), "cors_rules": bucket.cors_rules},
            remediation=(
                "Restrict AllowedOrigins to known frontends; avoid '*' with credentials "
                "or sensitive buckets."
            ),
        )
    ]


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
