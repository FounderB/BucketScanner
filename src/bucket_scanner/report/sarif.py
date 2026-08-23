"""SARIF 2.1.0 report emitter."""

from __future__ import annotations

import json
from pathlib import Path

from bucket_scanner.models import ScanReport, Severity

SARIF_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _artifact_uri(report: ScanReport, bucket: str | None) -> str:
    target = bucket or report.folder_id
    if report.cloud == "aws":
        return f"arn:aws:s3:::{target}"
    if report.cloud == "azure":
        return f"azure://blob/{target}"
    return f"yc://object-storage/{target}"


def render_sarif(report: ScanReport) -> dict:
    rules = {}
    results = []

    for finding in report.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "defaultConfiguration": {"level": SARIF_SEVERITY[finding.severity]},
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_SEVERITY[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _artifact_uri(report, finding.bucket)
                            }
                        }
                    }
                ],
            }
        )

    for chain in report.chains:
        rules[chain.chain_id] = {
            "id": chain.chain_id,
            "name": chain.chain_id,
            "shortDescription": {"text": chain.title},
            "fullDescription": {"text": chain.message},
            "defaultConfiguration": {"level": SARIF_SEVERITY[chain.severity]},
        }
        results.append(
            {
                "ruleId": chain.chain_id,
                "level": SARIF_SEVERITY[chain.severity],
                "message": {"text": chain.message},
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool,
                        "version": report.version,
                        "informationUri": "https://github.com/FounderB/BucketScanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(render_sarif(report), indent=2), encoding="utf-8")
