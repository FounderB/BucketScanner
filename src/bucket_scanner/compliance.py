"""Compliance framework mappings for findings."""

from __future__ import annotations

from typing import Any

# rule_id -> list of normalized compliance tag strings (SARIF properties.tags)
COMPLIANCE_TAGS: dict[str, list[str]] = {
    "acl/public-read": ["CIS-1.5", "NIST-AC-3", "SOC2-CC6.1"],
    "acl/public-read-write": ["CIS-1.5", "NIST-AC-3", "SOC2-CC6.1"],
    "policy/overly-permissive": ["CIS-1.5", "NIST-AC-6", "SOC2-CC6.1"],
    "encryption/disabled": ["CIS-3.11", "NIST-SC-28", "SOC2-CC6.7"],
    "logging/disabled": ["CIS-3.8", "NIST-AU-2", "SOC2-CC7.2"],
    "versioning/disabled": ["CIS-3.11", "NIST-CP-9", "SOC2-A1.2"],
    "iam/stale-static-key": ["CIS-4.3", "NIST-IA-5", "SOC2-CC6.1"],
    "iam/over-privileged-sa": ["CIS-4.2", "NIST-AC-6", "SOC2-CC6.3"],
    "probe/anonymous-list": ["CIS-1.5", "NIST-AC-3"],
    "probe/anonymous-read-confirmed": ["CIS-1.5", "NIST-AC-3"],
    "aws/block-public-access-incomplete": ["CIS-1.5", "NIST-AC-3"],
    "aws/account-public-access-incomplete": ["CIS-1.5", "NIST-AC-3"],
    "azure/container-public-access": ["CIS-1.5", "NIST-AC-3"],
    "azure/account-public-access-enabled": ["CIS-1.5", "NIST-AC-3"],
    "gcs/iam-public-principal": ["CIS-1.5", "NIST-AC-3"],
    "gcs/public-access-prevention-not-enforced": ["CIS-1.5", "NIST-AC-3"],
    "gcs/uniform-access-disabled": ["CIS-3.11", "NIST-AC-3"],
    "secrets/yc-env-var": ["NIST-IA-5", "SOC2-CC6.1"],
    "secrets/yc-static-key": ["NIST-IA-5", "SOC2-CC6.1"],
    "secrets/aws-env-var": ["NIST-IA-5", "SOC2-CC6.1"],
    "secrets/aws-access-key-id": ["NIST-IA-5", "SOC2-CC6.1"],
    "secrets/azure-env-var": ["NIST-IA-5", "SOC2-CC6.1"],
    "chain/silent-exfil": ["NIST-AC-3", "NIST-AU-2", "NIST-CP-9"],
    "chain/leaked-credentials-exposure": ["NIST-IA-5", "NIST-AC-3"],
}


def _framework_buckets(tags: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {"cis": [], "nist_800_53": [], "soc2": []}
    for tag in tags:
        if tag.startswith("CIS-"):
            buckets["cis"].append(tag.removeprefix("CIS-"))
        elif tag.startswith("NIST-"):
            buckets["nist_800_53"].append(tag.removeprefix("NIST-"))
        elif tag.startswith("SOC2-"):
            buckets["soc2"].append(tag.removeprefix("SOC2-"))
    return {key: value for key, value in buckets.items() if value}


def sarif_rule_properties(rule_id: str) -> dict[str, Any]:
    tags = COMPLIANCE_TAGS.get(rule_id, [])
    if not tags:
        return {"tags": ["security"]}
    return {
        "tags": ["security", *tags],
        "compliance": _framework_buckets(tags),
    }
