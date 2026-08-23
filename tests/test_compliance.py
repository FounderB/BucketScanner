"""Compliance tag tests."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.compliance import (
    build_compliance_report,
    compliance_tags_for_rule,
    sarif_rule_properties,
)
from bucket_scanner.config import load_config
from bucket_scanner.report.sarif import render_sarif
from bucket_scanner.scan import run_scan

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_sarif_rule_properties_acl():
    props = sarif_rule_properties("acl/public-read")
    assert "CIS-1.5" in props["tags"]
    assert props["compliance"]["cis"] == ["1.5"]
    assert props["compliance"]["nist_800_53"] == ["AC-3"]


def test_sarif_includes_compliance_tags():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    sarif = render_sarif(report)
    rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "CIS-1.5" in rules["acl/public-read"]["properties"]["tags"]
    results = sarif["runs"][0]["results"]
    acl_result = next(item for item in results if item["ruleId"] == "acl/public-read")
    assert "CIS-1.5" in acl_result["properties"]["tags"]


def test_iac_compliance_tags():
    props = sarif_rule_properties("iac/acl-drift")
    assert "NIST-CM-6" in props["tags"]


def test_tracefuse_compliance_fallback():
    tags = compliance_tags_for_rule("tracefuse/secrets/yc-token")
    assert "NIST-IA-5" in tags


def test_compliance_report_export():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    payload = build_compliance_report(report)
    assert payload["summary"]["total_findings"] == len(report.findings)
    assert "CIS-1.5" in payload["controls"]
