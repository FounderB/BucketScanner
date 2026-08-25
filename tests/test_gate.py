"""Baseline delta and suppression tests."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

from click.testing import CliRunner

from bucket_scanner.cli import main
from bucket_scanner.config import ScanConfig, load_config
from bucket_scanner.gate import (
    Suppression,
    apply_gate,
    apply_suppressions,
    compute_delta,
    finding_fingerprint,
    write_baseline_report,
)
from bucket_scanner.models import Finding, ScanReport, ScanSummary, Severity
from bucket_scanner.scan import run_scan, should_fail

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def _sample_report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        version="0.10.0",
        cloud="yandex",
        folder_id="b1gTEST",
        findings=findings,
        summary=ScanSummary(total=len(findings), high=len(findings)),
    )


def test_finding_fingerprint_stable():
    finding = Finding(
        rule_id="acl/public-read",
        title="t",
        severity=Severity.HIGH,
        message="m",
        bucket="b1",
    )
    assert finding_fingerprint(finding) == "acl/public-read|b1|"


def test_apply_suppressions_filters_matching_rule():
    findings = [
        Finding(
            rule_id="logging/disabled",
            title="t",
            severity=Severity.MEDIUM,
            message="m",
            bucket="cdn-assets",
        ),
        Finding(
            rule_id="encryption/disabled",
            title="t",
            severity=Severity.HIGH,
            message="m",
            bucket="secret",
        ),
    ]
    suppressions = [
        Suppression(rule="logging/disabled", bucket="cdn-assets", reason="accepted"),
    ]
    kept, suppressed_rows, warnings = apply_suppressions(findings, suppressions)
    assert len(suppressed_rows) == 1
    assert len(kept) == 1
    assert kept[0].rule_id == "encryption/disabled"
    assert not warnings


def test_suppression_expires():
    finding = Finding(
        rule_id="logging/disabled",
        title="t",
        severity=Severity.LOW,
        message="m",
        bucket="b1",
    )
    expired = Suppression(
        rule="logging/disabled",
        bucket="b1",
        expires=date.today() - timedelta(days=1),
    )
    kept, suppressed_rows, _warnings = apply_suppressions([finding], [expired])
    assert len(suppressed_rows) == 0
    assert len(kept) == 1


def test_suppression_glob_bucket():
    finding = Finding(
        rule_id="logging/disabled",
        title="t",
        severity=Severity.LOW,
        message="m",
        bucket="cdn-assets-prod",
    )
    kept, suppressed_rows, _ = apply_suppressions(
        [finding],
        [Suppression(rule="logging/disabled", bucket="cdn-*", reason="cdn fleet")],
    )
    assert len(kept) == 0
    assert len(suppressed_rows) == 1


def test_compute_delta_new_findings():
    baseline = _sample_report(
        [
            Finding(
                rule_id="acl/public-read",
                title="t",
                severity=Severity.CRITICAL,
                message="m",
                bucket="old",
            )
        ]
    )
    current = _sample_report(
        baseline.findings
        + [
            Finding(
                rule_id="encryption/disabled",
                title="t",
                severity=Severity.HIGH,
                message="m",
                bucket="new",
            )
        ]
    )
    new_findings, new_chains = compute_delta(current, baseline)
    assert len(new_findings) == 1
    assert new_findings[0].rule_id == "encryption/disabled"


def test_apply_gate_with_baseline(tmp_path: Path):
    report = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    baseline_path = tmp_path / "baseline.json"
    write_baseline_report(report, baseline_path)

    report2 = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    gated = apply_gate(report2, suppressions=[], baseline_path=baseline_path)
    assert gated.summary.new == 0
    assert gated.baseline_path == str(baseline_path)


def test_should_fail_new_only():
    report = ScanReport(
        version="0.10.0",
        cloud="yandex",
        folder_id="b1g",
        findings=[
            Finding(
                rule_id="acl/public-read",
                title="t",
                severity=Severity.CRITICAL,
                message="legacy",
                bucket="b1",
            )
        ],
        new_findings=[
            Finding(
                rule_id="encryption/disabled",
                title="t",
                severity=Severity.HIGH,
                message="new",
                bucket="b2",
            )
        ],
        summary=ScanSummary(critical=1, high=1),
    )
    assert should_fail(report, Severity.HIGH, new_only=False) is True
    assert should_fail(report, Severity.HIGH, new_only=True) is True
    report_no_new = report.model_copy(update={"new_findings": []})
    assert should_fail(report_no_new, Severity.HIGH, new_only=True) is False


def test_load_suppressions_from_config(tmp_path: Path):
    config_path = tmp_path / ".bucket-scanner.toml"
    config_path.write_text(
        """
[[scan.suppressions]]
rule = "logging/disabled"
bucket = "cdn"
reason = "test"
""",
        encoding="utf-8",
    )
    app = load_config(config_path)
    assert len(app.scan.suppressions) == 1
    assert app.scan.suppressions[0].rule == "logging/disabled"


def test_cli_write_baseline(tmp_path: Path):
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    result = runner.invoke(
        main,
        [
            "scan",
            "--fixture",
            str(FIXTURE),
            "--write-baseline",
            str(baseline),
            "-q",
        ],
    )
    assert result.exit_code == 1
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert payload["report_schema"] == "1.0"
    assert payload["findings"]


def test_cli_fail_on_new_without_baseline():
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", "--fixture", str(FIXTURE), "--fail-on", "new", "-q"],
    )
    assert result.exit_code == 2
    assert "baseline" in result.output.lower()
