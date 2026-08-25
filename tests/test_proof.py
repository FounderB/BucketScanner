"""Tests for proof-log triage helpers."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from bucket_scanner.cli import main
from bucket_scanner.config import ScanConfig
from bucket_scanner.gate import finding_fingerprint
from bucket_scanner.proof import load_log, set_status, summarize, upsert_from_report, write_log
from bucket_scanner.scan import run_scan

FIXTURE = Path("examples/demo-vulnerable/fixture.toml")


def test_upsert_and_summary(tmp_path: Path):
    report = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    entries: dict = {}
    entries, new_count, refreshed = upsert_from_report(report, entries)
    assert new_count == len(report.findings)
    assert refreshed == 0
    log_path = tmp_path / "fp-log.jsonl"
    write_log(log_path, entries)
    loaded = load_log(log_path)
    assert len(loaded) == len(report.findings)

    entries2, new2, refreshed2 = upsert_from_report(report, loaded)
    assert new2 == 0
    assert refreshed2 == len(report.findings)
    summary = summarize(entries2)
    assert summary["total"] == len(report.findings)
    assert summary["unreviewed"] == len(report.findings)


def test_set_status_false_positive(tmp_path: Path):
    report = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    entries, _, _ = upsert_from_report(report, {})
    fp = finding_fingerprint(report.findings[0])
    set_status(entries, fp, "false_positive", notes="CDN intentional")
    assert entries[fp]["status"] == "false_positive"
    assert entries[fp]["notes"] == "CDN intentional"
    write_log(tmp_path / "log.jsonl", entries)
    assert summarize(entries)["false_positive"] == 1


def test_cli_proof_log_update(tmp_path: Path):
    report = run_scan(folder_id=None, fixture=FIXTURE, config=ScanConfig())
    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json(), encoding="utf-8")
    log_path = tmp_path / "fp-log.jsonl"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["proof-log", "update", "--report", str(report_path), "--log", str(log_path)],
    )
    assert result.exit_code == 0, result.output
    assert log_path.is_file()
    lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]
    assert lines
    assert all(row["status"] == "unreviewed" for row in lines)
