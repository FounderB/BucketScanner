"""Tracefuse report integration for cross-stack findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bucket_scanner.models import Finding, Severity

YC_MARKERS = ("yc_", "yandex", "ycaJ", "storage.yandexcloud", "authorized_key")


def load_tracefuse_report(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_findings = data.get("findings", data if isinstance(data, list) else [])
    findings: list[Finding] = []
    for item in raw_findings:
        if not _is_yc_related(item):
            continue
        findings.append(
            Finding(
                rule_id=f"tracefuse/{item.get('rule_id', 'finding')}",
                title=item.get("title", "Tracefuse YC-related finding"),
                severity=_map_severity(item.get("severity", "high")),
                message=item.get("message", "Imported from Tracefuse report."),
                resource=item.get("resource") or item.get("file"),
                evidence={"source": str(path), "imported": _sanitize(item)},
                remediation=item.get("remediation")
                or "Remove secret from repo history and rotate credentials.",
            )
        )
    return findings


def _is_yc_related(item: dict[str, Any]) -> bool:
    blob = json.dumps(item, ensure_ascii=False).lower()
    return any(marker.lower() in blob for marker in YC_MARKERS)


def _map_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.HIGH


def _sanitize(item: dict[str, Any]) -> dict[str, Any]:
    cleaned = {key: item.get(key) for key in ("rule_id", "title", "severity", "file", "resource")}
    return {key: value for key, value in cleaned.items() if value is not None}
