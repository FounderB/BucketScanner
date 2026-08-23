"""JSON report emitter."""

from __future__ import annotations

from bucket_scanner.models import ScanReport


def render_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)
