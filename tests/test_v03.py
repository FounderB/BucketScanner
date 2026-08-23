"""v0.3 feature tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from bucket_scanner.chains import compose_chains
from bucket_scanner.checks import check_bucket
from bucket_scanner.cli import main
from bucket_scanner.config import load_config
from bucket_scanner.fixture import load_fixture
from bucket_scanner.models import Severity
from bucket_scanner.notify import NotifyConfig, build_summary_text, should_notify
from bucket_scanner.report.prometheus import render_prometheus
from bucket_scanner.scan import run_scan
from bucket_scanner.secrets import scan_repo
from bucket_scanner.tracefuse import load_tracefuse_report

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")
REPO = Path("examples/demo-vulnerable/repo")
TRACEfuse = Path("examples/demo-vulnerable/tracefuse-report.json")


def test_scan_repo_finds_yc_env():
    findings = scan_repo(REPO)
    rules = {item.rule_id for item in findings}
    assert "secrets/yc-env-var" in rules


def test_tracefuse_report_import():
    findings = load_tracefuse_report(TRACEfuse)
    assert len(findings) == 1
    assert findings[0].rule_id.startswith("tracefuse/")


def test_leaked_credentials_chain():
    _, buckets, _ = load_fixture(FIXTURE)
    bucket_findings = check_bucket(buckets[0])
    secret_findings = scan_repo(REPO)
    findings = bucket_findings + secret_findings
    chains = compose_chains(buckets[:1], findings)
    assert any(item.chain_id == "chain/leaked-credentials-exposure" for item in chains)


def test_prometheus_format():
    report = run_scan(
        folder_id=None,
        fixture=FIXTURE,
        config=load_config().scan,
        repo_path=REPO,
    )
    body = render_prometheus(report)
    assert "bucket_scanner_score" in body
    assert "bucket_scanner_findings_total" in body
    assert 'severity="critical"' in body


def test_notify_summary():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    text = build_summary_text(report)
    assert "Bucket Scanner" in text
    assert "score:" in text


def test_should_notify_on_high():
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    assert should_notify(report, NotifyConfig(min_severity=Severity.HIGH))


@patch("bucket_scanner.notify.httpx.post")
def test_send_webhook(mock_post):
    mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
    report = run_scan(folder_id=None, fixture=FIXTURE, config=load_config().scan)
    from bucket_scanner.notify import send_webhook

    send_webhook("https://example.com/hook", report)
    mock_post.assert_called_once()


def test_cli_scan_with_repo_and_prometheus(tmp_path: Path):
    runner = CliRunner()
    prom = tmp_path / "metrics.prom"
    result = runner.invoke(
        main,
        [
            "scan",
            "--fixture",
            str(FIXTURE),
            "--repo",
            str(REPO),
            "--tracefuse-report",
            str(TRACEfuse),
            "--prometheus",
            str(prom),
            "-q",
        ],
    )
    assert result.exit_code == 1
    assert "bucket_scanner_score" in prom.read_text(encoding="utf-8")


def test_full_stack_scan_rules():
    report = run_scan(
        folder_id=None,
        fixture=FIXTURE,
        config=load_config().scan,
        repo_path=REPO,
        tracefuse_report=TRACEfuse,
        terraform_path=Path("examples/demo-vulnerable/terraform"),
    )
    rules = {finding.rule_id for finding in report.findings}
    assert "secrets/yc-env-var" in rules
    assert any(rule.startswith("tracefuse/") for rule in rules)
    assert "iac/acl-drift" in rules
    chain_ids = {item.chain_id for item in report.chains}
    assert "chain/leaked-credentials-exposure" in chain_ids
