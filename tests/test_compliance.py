"""Compliance tag tests."""

from __future__ import annotations

from pathlib import Path

from bucket_scanner.compliance import sarif_rule_properties
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
