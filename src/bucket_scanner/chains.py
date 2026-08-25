"""Compose compound misconfiguration chains."""

from __future__ import annotations

from bucket_scanner.models import BucketSnapshot, ChainFinding, Finding, Severity

PUBLIC_RULES = {
    "acl/public-read",
    "acl/public-read-write",
    "probe/anonymous-list",
    "probe/anonymous-read-confirmed",
    "policy/overly-permissive",
    "yc/anonymous-read-enabled",
    "yc/anonymous-list-enabled",
    "azure/container-public-access",
    "azure/account-public-access-enabled",
    "gcs/iam-public-principal",
    "aws/block-public-access-missing",
    "aws/account-public-access-missing",
}
PRIVILEGED_RULES = {
    "iam/over-privileged-sa",
}
SECRET_RULES = {
    "secrets/yc-env-var",
    "secrets/yc-static-key",
    "secrets/yc-sa-key-json",
    "secrets/aws-env-var",
    "secrets/aws-access-key-id",
    "secrets/aws-compat-key-in-yc-context",
}


def compose_chains(
    buckets: list[BucketSnapshot],
    findings: list[Finding],
) -> list[ChainFinding]:
    chains: list[ChainFinding] = []
    by_bucket: dict[str, list[Finding]] = {}
    global_rules = {finding.rule_id for finding in findings}
    global_privileged = [
        finding for finding in findings if finding.rule_id in PRIVILEGED_RULES
    ]

    for finding in findings:
        if finding.bucket:
            by_bucket.setdefault(finding.bucket, []).append(finding)

    for bucket in buckets:
        bucket_findings = by_bucket.get(bucket.name, [])
        rule_ids = {finding.rule_id for finding in bucket_findings}
        is_public = bool(rule_ids & PUBLIC_RULES)
        no_logging = "logging/disabled" in rule_ids
        no_versioning = "versioning/disabled" in rule_ids

        if is_public and no_logging and no_versioning:
            chain_rules = PUBLIC_RULES | {"logging/disabled", "versioning/disabled"}
            chains.append(
                ChainFinding(
                    chain_id="chain/silent-exfil",
                    title="Silent exfil path",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Bucket '{bucket.name}' is exposed while logging and versioning are off — "
                        "exfiltration may go unnoticed and objects cannot be rolled back."
                    ),
                    rule_ids=sorted(rule_ids & chain_rules),
                    buckets=[bucket.name],
                )
            )
        elif is_public and no_logging:
            chains.append(
                ChainFinding(
                    chain_id="chain/public-no-audit",
                    title="Public bucket without audit trail",
                    severity=Severity.HIGH,
                    message=(
                        f"Bucket '{bucket.name}' is reachable anonymously "
                        "but access logging is disabled."
                    ),
                    rule_ids=sorted(rule_ids),
                    buckets=[bucket.name],
                )
            )

        if is_public and (rule_ids & PRIVILEGED_RULES or global_privileged):
            priv_rules = sorted((rule_ids & PRIVILEGED_RULES) | {f.rule_id for f in global_privileged})
            pub_rules = sorted(rule_ids & PUBLIC_RULES)
            chains.append(
                ChainFinding(
                    chain_id="chain/privileged-public-blast",
                    title="Over-privileged principal meets public storage",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Bucket '{bucket.name}' is publicly exposed while an over-privileged "
                        "service account / IAM principal exists in scope — blast radius is elevated."
                    ),
                    rule_ids=sorted(set(priv_rules + pub_rules)),
                    buckets=[bucket.name],
                )
            )

    leaked = global_rules & SECRET_RULES
    tracefuse_leaks = {rule for rule in global_rules if rule.startswith("tracefuse/")}
    if (leaked or tracefuse_leaks) and _has_public_exposure(buckets, by_bucket):
        public_buckets = [
            bucket.name
            for bucket in buckets
            if {finding.rule_id for finding in by_bucket.get(bucket.name, [])} & PUBLIC_RULES
        ]
        chains.append(
            ChainFinding(
                chain_id="chain/leaked-credentials-exposure",
                title="Leaked credentials meet public storage",
                severity=Severity.CRITICAL,
                message=(
                    "Cloud credential material was found in repo or Tracefuse report while "
                    f"public buckets exist ({', '.join(public_buckets[:3])}). "
                    "Assume keys are compromised."
                ),
                rule_ids=sorted(leaked | tracefuse_leaks),
                buckets=public_buckets,
            )
        )

    return chains


def _has_public_exposure(
    buckets: list[BucketSnapshot],
    by_bucket: dict[str, list[Finding]],
) -> bool:
    for bucket in buckets:
        rule_ids = {finding.rule_id for finding in by_bucket.get(bucket.name, [])}
        if rule_ids & PUBLIC_RULES:
            return True
    return False
