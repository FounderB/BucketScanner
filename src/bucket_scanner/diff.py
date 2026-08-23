"""Compare Terraform intent against live or fixture bucket state."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.models import BucketSnapshot, Finding, Severity
from bucket_scanner.terraform import BPA_KEYS, parse_terraform_dir

PUBLIC_ACLS = {"public-read", "public-read-write", "public"}


def diff_terraform(
    terraform_path: Path,
    buckets: list[BucketSnapshot],
) -> list[Finding]:
    intents = parse_terraform_dir(terraform_path)
    if not intents:
        return [
            Finding(
                rule_id="iac/no-buckets-declared",
                title="No buckets declared in Terraform",
                severity=Severity.INFO,
                message=f"No storage bucket resources found under {terraform_path}.",
                evidence={"path": str(terraform_path)},
                remediation=(
                    "Add storage resources or point --terraform at the correct module path."
                ),
            )
        ]

    declared = {item.bucket for item in intents if item.bucket and not item.bucket.startswith("$")}
    live = {bucket.name for bucket in buckets}
    findings: list[Finding] = []

    for name in sorted(live - declared):
        findings.append(
            Finding(
                rule_id="iac/shadow-bucket",
                title="Shadow bucket not declared in Terraform",
                severity=Severity.HIGH,
                message=f"Bucket '{name}' exists live but is absent from Terraform.",
                bucket=name,
                evidence={"declared_in": str(terraform_path)},
                remediation="Import the bucket into Terraform or delete if orphaned.",
            )
        )

    for intent in intents:
        if not intent.bucket or intent.bucket.startswith("$"):
            continue
        if intent.bucket not in live:
            findings.append(
                Finding(
                    rule_id="iac/ghost-bucket",
                    title="Ghost bucket declared but missing live",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Terraform declares bucket '{intent.bucket}' "
                        f"but it was not found in the scan scope."
                    ),
                    bucket=intent.bucket,
                    evidence={"source_file": intent.source_file, "resource": intent.resource_name},
                    remediation="Apply Terraform or remove stale resource blocks.",
                )
            )
            continue

        live_bucket = next(item for item in buckets if item.name == intent.bucket)
        declared_acl = (intent.acl or "private").lower()
        live_acl = (live_bucket.acl or "unknown").lower()
        if declared_acl == "private" and live_acl in PUBLIC_ACLS:
            findings.append(
                Finding(
                    rule_id="iac/acl-drift",
                    title="Declared private but live bucket is public",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Terraform declares '{intent.bucket}' as private "
                        f"but live ACL is '{live_acl}'."
                    ),
                    bucket=intent.bucket,
                    evidence={
                        "declared_acl": declared_acl,
                        "live_acl": live_acl,
                        "source_file": intent.source_file,
                    },
                    remediation="Reconcile Terraform and live ACL/policy before next deploy.",
                )
            )
        elif intent.acl and live_acl not in {"unknown", live_acl} and live_acl in PUBLIC_ACLS:
            findings.append(
                Finding(
                    rule_id="iac/acl-drift",
                    title="Terraform ACL drift",
                    severity=Severity.HIGH,
                    message=(
                        f"Terraform declares acl='{declared_acl}' for '{intent.bucket}' "
                        f"but live ACL is '{live_acl}'."
                    ),
                    bucket=intent.bucket,
                    evidence={
                        "declared_acl": declared_acl,
                        "live_acl": live_acl,
                        "source_file": intent.source_file,
                    },
                    remediation="Run terraform plan and align bucket ACL with intent.",
                )
            )

        findings.extend(_check_bpa_drift(intent, live_bucket, terraform_path))
        findings.extend(_check_azure_drift(intent, live_bucket))
        findings.extend(_check_gcs_drift(intent, live_bucket))

    return findings


def _bpa_fully_enabled(config: dict[str, bool] | None) -> bool:
    if not config:
        return False
    return all(config.get(key, False) for key in BPA_KEYS)


def _check_bpa_drift(
    intent,
    live_bucket: BucketSnapshot,
    terraform_path: Path,
) -> list[Finding]:
    if live_bucket.cloud != "aws":
        return []
    declared = intent.block_public_access
    if not declared or not _bpa_fully_enabled(declared):
        return []
    live = live_bucket.block_public_access or {}
    if _bpa_fully_enabled(live):
        return []
    return [
        Finding(
            rule_id="iac/bpa-drift",
            title="Terraform Block Public Access drift",
            severity=Severity.HIGH,
            message=(
                f"Terraform declares full Block Public Access for '{intent.bucket}' "
                "but live settings are incomplete."
            ),
            bucket=intent.bucket,
            evidence={
                "declared_block_public_access": declared,
                "live_block_public_access": live,
                "source_file": intent.source_file,
                "declared_in": str(terraform_path),
            },
            remediation="Apply Terraform or align live bucket Block Public Access with intent.",
        )
    ]


def _check_azure_drift(intent, live_bucket: BucketSnapshot) -> list[Finding]:
    if live_bucket.cloud != "azure":
        return []
    findings: list[Finding] = []
    declared_access = (intent.container_access_type or "private").lower()
    live_bpa = live_bucket.block_public_access or {}
    live_public = str(live_bpa.get("public_access", "off")).lower()
    if declared_access in {"private", "off"} and live_public in {"container", "blob"}:
        findings.append(
            Finding(
                rule_id="iac/container-access-drift",
                title="Terraform container access drift",
                severity=Severity.CRITICAL,
                message=(
                    f"Terraform declares '{intent.bucket}' as private "
                    f"but live public access is '{live_public}'."
                ),
                bucket=intent.bucket,
                evidence={
                    "declared_access": declared_access,
                    "live_public_access": live_public,
                    "source_file": intent.source_file,
                },
                remediation="Set container_access_type=private and disable blob public access.",
            )
        )
    return findings


def _check_gcs_drift(intent, live_bucket: BucketSnapshot) -> list[Finding]:
    if live_bucket.cloud != "gcs":
        return []
    findings: list[Finding] = []
    live_bpa = live_bucket.block_public_access or {}
    declared_pap = intent.public_access_prevention
    live_pap = str(live_bpa.get("public_access_prevention", "unknown")).lower()
    if declared_pap and declared_pap.lower() == "enforced" and live_pap != "enforced":
        findings.append(
            Finding(
                rule_id="iac/pap-drift",
                title="Terraform public access prevention drift",
                severity=Severity.HIGH,
                message=(
                    f"Terraform enforces public access prevention on '{intent.bucket}' "
                    f"but live setting is '{live_pap}'."
                ),
                bucket=intent.bucket,
                evidence={
                    "declared_pap": declared_pap,
                    "live_pap": live_pap,
                    "source_file": intent.source_file,
                },
                remediation="Apply Terraform or enforce publicAccessPrevention on the bucket.",
            )
        )
    if intent.uniform_bucket_level_access is True:
        live_ubla = live_bpa.get("uniform_bucket_level_access")
        if live_ubla is False:
            findings.append(
                Finding(
                    rule_id="iac/ubla-drift",
                    title="Terraform uniform bucket-level access drift",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Terraform enables uniform bucket-level access on '{intent.bucket}' "
                        "but live setting is disabled."
                    ),
                    bucket=intent.bucket,
                    evidence={
                        "declared_ubla": True,
                        "live_ubla": False,
                        "source_file": intent.source_file,
                    },
                    remediation="Enable uniform bucket-level access in GCS or update Terraform.",
                )
            )
    if intent.iam_public and not live_bpa.get("iam_public"):
        findings.append(
            Finding(
                rule_id="iac/iam-public-drift",
                title="Terraform declares public IAM but live is private",
                severity=Severity.MEDIUM,
                message=(
                    f"Terraform grants public IAM on '{intent.bucket}' "
                    "but live scan shows no public IAM principal."
                ),
                bucket=intent.bucket,
                evidence={"source_file": intent.source_file},
                remediation="Reconcile Terraform IAM bindings with live bucket IAM.",
            )
        )
    elif not intent.iam_public and live_bpa.get("iam_public"):
        findings.append(
            Finding(
                rule_id="iac/iam-public-drift",
                title="Live bucket has public IAM not declared in Terraform",
                severity=Severity.CRITICAL,
                message=(
                    f"Live bucket '{intent.bucket}' allows public IAM principals "
                    "but Terraform does not declare them."
                ),
                bucket=intent.bucket,
                evidence={"source_file": intent.source_file, "live_iam_public": True},
                remediation="Remove public IAM bindings or declare them explicitly in Terraform.",
            )
        )
    return findings
