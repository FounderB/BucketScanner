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
    "iac/shadow-bucket": ["CIS-1.5", "NIST-CM-8", "SOC2-CC8.1"],
    "iac/ghost-bucket": ["NIST-CM-8", "SOC2-CC8.1"],
    "iac/acl-drift": ["CIS-1.5", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/bpa-drift": ["CIS-1.5", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/container-access-drift": ["CIS-1.5", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/pap-drift": ["CIS-1.5", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/ubla-drift": ["CIS-3.11", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/iam-public-drift": ["CIS-1.5", "NIST-CM-6", "SOC2-CC8.1"],
    "iac/no-buckets-declared": ["NIST-CM-8"],
    "tracefuse/secrets/yc-token": ["NIST-IA-5", "SOC2-CC6.1"],
    "tracefuse/secrets/aws-access-key": ["NIST-IA-5", "SOC2-CC6.1"],
    "tracefuse/secrets/azure-client-secret": ["NIST-IA-5", "SOC2-CC6.1"],
    "tracefuse/secrets/gcp-service-account-key": ["NIST-IA-5", "SOC2-CC6.1"],
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
    tags = compliance_tags_for_rule(rule_id)
    if not tags:
        return {"tags": ["security"]}
    return {
        "tags": ["security", *tags],
        "compliance": _framework_buckets(tags),
    }


def compliance_tags_for_rule(rule_id: str) -> list[str]:
    direct = COMPLIANCE_TAGS.get(rule_id)
    if direct:
        return direct
    if rule_id.startswith("tracefuse/"):
        base = rule_id.removeprefix("tracefuse/")
        for key, tags in COMPLIANCE_TAGS.items():
            if key.startswith("tracefuse/") and base.startswith(key.removeprefix("tracefuse/")):
                return tags
        return COMPLIANCE_TAGS.get("tracefuse/secrets/yc-token", [])
    return []


def build_compliance_report(report) -> dict[str, Any]:
    """Aggregate scan findings by compliance control tag."""
    controls: dict[str, list[dict[str, Any]]] = {}
    untagged: list[dict[str, Any]] = []

    for finding in report.findings:
        payload = {
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "bucket": finding.bucket,
            "message": finding.message,
        }
        tags = compliance_tags_for_rule(finding.rule_id)
        if not tags:
            untagged.append(payload)
            continue
        for tag in tags:
            controls.setdefault(tag, []).append(payload)

    for chain in report.chains:
        for rule_id in chain.rule_ids:
            payload = {
                "rule_id": rule_id,
                "severity": chain.severity.value,
                "title": chain.title,
                "chain_id": chain.chain_id,
                "buckets": chain.buckets,
                "message": chain.message,
            }
            tags = compliance_tags_for_rule(rule_id)
            if not tags:
                untagged.append(payload)
                continue
            for tag in tags:
                controls.setdefault(tag, []).append(payload)

    summary_controls = {
        tag: len(items) for tag, items in sorted(controls.items())
    }
    return {
        "tool": report.tool,
        "version": report.version,
        "cloud": report.cloud,
        "scope_id": report.folder_id,
        "scanned_at": report.scanned_at.isoformat(),
        "frameworks": ["cis", "nist_800_53", "soc2"],
        "controls": {
            tag: {"count": len(items), "findings": items}
            for tag, items in sorted(controls.items())
        },
        "untagged_findings": untagged,
        "summary": {
            "total_findings": len(report.findings),
            "total_chains": len(report.chains),
            "tagged_controls": len(controls),
            "untagged": len(untagged),
            "by_control": summary_controls,
        },
    }


def render_compliance_json(report) -> str:
    import json

    return json.dumps(build_compliance_report(report), indent=2)
