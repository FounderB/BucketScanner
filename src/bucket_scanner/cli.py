"""Bucket Scanner CLI entrypoint."""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console

from bucket_scanner import __version__
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import AppConfig, ScanConfig, load_config, write_default_config
from bucket_scanner.doctor import run_doctor
from bucket_scanner.explain import explain_rule
from bucket_scanner.models import ScanReport, Severity
from bucket_scanner.notify import NotifyConfig, notify_all
from bucket_scanner.report.human import render_human
from bucket_scanner.report.json_report import render_json
from bucket_scanner.report.prometheus import render_prometheus
from bucket_scanner.report.sarif import write_sarif
from bucket_scanner.scan import ScanError, run_scan, should_fail
from bucket_scanner.serve import run_metrics_server

console = Console()


def _load_app_config(config_path: Path | None) -> AppConfig:
    return load_config(config_path)


def _apply_scan_overrides(
    config: ScanConfig,
    *,
    folder_id: str | None = None,
    cloud: str | None = None,
    aws_region: str | None = None,
    aws_profile: str | None = None,
    probe: bool | None = None,
) -> None:
    if folder_id:
        config.folder_id = folder_id
    if cloud:
        config.cloud = CloudProvider.parse(cloud)
    if aws_region:
        config.aws_region = aws_region
    if aws_profile:
        config.aws_profile = aws_profile
    if probe:
        config.probe = True


def _iac_report(report: ScanReport) -> ScanReport:
    return report.model_copy(
        update={
            "findings": [item for item in report.findings if item.rule_id.startswith("iac/")],
            "chains": [],
        }
    )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="bucket-scanner")
def main() -> None:
    """Declared vs real — Object Storage security scanner (Yandex Cloud + AWS S3)."""


@main.command()
@click.option("--config", "config_path", type=click.Path(path_type=Path))
def doctor(config_path: Path | None) -> None:
    """Check credentials, folder access, and API reachability."""
    _ = _load_app_config(config_path)
    raise SystemExit(run_doctor(console))


@main.command()
@click.option("--folder-id", help="Yandex Cloud folder ID or AWS account scope label.")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region", help="AWS region for S3 API calls (default: us-east-1).")
@click.option("--aws-profile", help="AWS shared credentials profile name.")
@click.option(
    "--fixture",
    type=click.Path(exists=True, path_type=Path),
    help="Offline demo fixture.",
)
@click.option("--config", "config_path", type=click.Path(path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON report.")
@click.option("--sarif", type=click.Path(path_type=Path), help="Write SARIF 2.1.0 report to path.")
@click.option(
    "--prometheus",
    "prometheus_path",
    type=click.Path(path_type=Path),
    help="Write Prometheus metrics to path.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default=None,
)
@click.option("--probe", is_flag=True, help="Anonymous reachability checks (opt-in).")
@click.option(
    "--terraform",
    "terraform_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Compare live/fixture state against Terraform intent.",
)
@click.option("--repo", "repo_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--tracefuse-report", type=click.Path(exists=True, path_type=Path))
@click.option("--webhook", help="POST JSON summary to webhook URL on findings.")
@click.option("--telegram-token")
@click.option("--telegram-chat-id")
@click.option(
    "--notify/--no-notify",
    default=False,
    help="Send configured webhook/Telegram alerts.",
)
@click.option("-q", "--quiet", is_flag=True, help="Minimal output for CI.")
def scan(
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
    as_json: bool,
    sarif: Path | None,
    prometheus_path: Path | None,
    fail_on: str | None,
    probe: bool,
    terraform_path: Path | None,
    repo_path: Path | None,
    tracefuse_report: Path | None,
    webhook: str | None,
    telegram_token: str | None,
    telegram_chat_id: str | None,
    notify: bool,
    quiet: bool,
) -> None:
    """Scan Object Storage buckets in a folder."""
    app_config = _load_app_config(config_path)
    config = app_config.scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
        probe=probe,
    )
    threshold = Severity(fail_on.lower()) if fail_on else config.fail_on

    try:
        report = run_scan(
            folder_id=config.folder_id,
            fixture=fixture,
            config=config,
            terraform_path=terraform_path,
            repo_path=repo_path,
            tracefuse_report=tracefuse_report,
        )
    except (ScanError, FileNotFoundError, ValueError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2) from exc

    if as_json:
        click.echo(render_json(report))
    elif not quiet:
        render_human(report, console)

    if sarif:
        write_sarif(report, sarif)
        if not quiet and not as_json:
            console.print(f"[green]SARIF written to[/green] {sarif}")

    if prometheus_path:
        prometheus_path.write_text(render_prometheus(report), encoding="utf-8")
        if not quiet and not as_json:
            console.print(f"[green]Prometheus metrics written to[/green] {prometheus_path}")

    notify_config = NotifyConfig(
        webhook_url=webhook or app_config.notify.webhook_url,
        telegram_bot_token=telegram_token or app_config.notify.telegram_bot_token,
        telegram_chat_id=telegram_chat_id or app_config.notify.telegram_chat_id,
        min_severity=app_config.notify.min_severity,
    )
    if notify or webhook or (telegram_token and telegram_chat_id):
        sent = notify_all(report, notify_config)
        if sent and not quiet:
            console.print(f"[green]Notifications sent via[/green] {', '.join(sent)}")

    if should_fail(report, threshold):
        raise SystemExit(1)


@main.command()
@click.option("--folder-id")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region")
@click.option("--aws-profile")
@click.option("--fixture", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path))
@click.option("--addr", default=None, help="Listen address, e.g. 127.0.0.1:9090")
@click.option("--interval", default=None, type=int, help="Rescan interval in seconds.")
@click.option(
    "--terraform",
    "terraform_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option("--repo", "repo_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--tracefuse-report", type=click.Path(exists=True, path_type=Path))
def serve(
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
    addr: str | None,
    interval: int | None,
    terraform_path: Path | None,
    repo_path: Path | None,
    tracefuse_report: Path | None,
) -> None:
    """Expose /metrics and /health for Prometheus and Grafana."""
    app_config = _load_app_config(config_path)
    config = app_config.scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    if terraform_path:
        config.terraform_path = terraform_path
    if repo_path:
        config.repo_path = repo_path
    if tracefuse_report:
        config.tracefuse_report = tracefuse_report
    listen = addr or app_config.serve.addr
    every = interval if interval is not None else app_config.serve.interval_seconds
    if not config.folder_id and not fixture and config.cloud != CloudProvider.AWS:
        console.print("[red]error:[/red] --folder-id or --fixture is required")
        raise SystemExit(2)
    console.print(f"[cyan]Serving[/cyan] http://{listen}/metrics")
    run_metrics_server(addr=listen, config=config, fixture=fixture, interval_seconds=every)


@main.command()
@click.argument("bucket")
@click.option("--folder-id")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region")
@click.option("--aws-profile")
@click.option("--fixture", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path))
def inspect(
    bucket: str,
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
) -> None:
    """Deep-dive report for a single bucket."""
    config = _load_app_config(config_path).scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    report = run_scan(folder_id=config.folder_id, fixture=fixture, config=config)
    matches = [item for item in report.findings if item.bucket == bucket]
    if not matches:
        console.print(f"[yellow]No findings for bucket[/yellow] {bucket}")
        raise SystemExit(0)
    for finding in matches:
        console.print(f"[bold]{finding.severity.value.upper()}[/bold] {finding.rule_id}")
        console.print(f"  {finding.message}")
        if finding.remediation:
            console.print(f"  [green]fix:[/green] {finding.remediation}")
    raise SystemExit(0)


@main.command()
@click.option("--sa-id", required=True, help="Service account ID for blast-radius graph.")
@click.option("--folder-id")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region")
@click.option("--aws-profile")
@click.option("--fixture", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path))
def chain(
    sa_id: str,
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
) -> None:
    """Map reachable buckets and risk chains from one service account."""
    config = _load_app_config(config_path).scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    if not config.folder_id and not fixture and config.cloud != CloudProvider.AWS:
        console.print("[red]error:[/red] --folder-id, --fixture, or config folder_id is required")
        raise SystemExit(2)
    report = run_scan(folder_id=config.folder_id, fixture=fixture, config=config)
    findings = [item for item in report.findings if item.resource == sa_id or sa_id in item.message]
    if not findings:
        console.print(f"[yellow]No findings linked to service account[/yellow] {sa_id}")
        raise SystemExit(0)
    for finding in findings:
        console.print(
            f"[bold]{finding.severity.value.upper()}[/bold] "
            f"{finding.rule_id}: {finding.message}"
        )
    raise SystemExit(0)


@main.command("list")
@click.option("--folder-id")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region")
@click.option("--aws-profile")
@click.option("--fixture", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path))
def list_buckets(
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
) -> None:
    """Inventory summary for a folder."""
    config = _load_app_config(config_path).scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    report = run_scan(folder_id=config.folder_id, fixture=fixture, config=config)
    for bucket in report.buckets:
        flags = []
        if bucket.region:
            flags.append(f"region={bucket.region}")
        if bucket.acl:
            flags.append(f"acl={bucket.acl}")
        if bucket.encryption_enabled:
            flags.append("encrypted")
        if bucket.versioning_enabled:
            flags.append("versioned")
        if bucket.logging_enabled:
            flags.append("logged")
        console.print(f"{bucket.name}  [{' · '.join(flags) if flags else 'no metadata'}]")


@main.command()
@click.argument("terraform_path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--folder-id")
@click.option("--cloud", type=click.Choice(["yandex", "aws"], case_sensitive=False), default=None)
@click.option("--aws-region")
@click.option("--aws-profile")
@click.option("--fixture", type=click.Path(exists=True, path_type=Path))
@click.option("--config", "config_path", type=click.Path(path_type=Path))
@click.option("--json", "as_json", is_flag=True)
@click.option(
    "--fail-on",
    type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False),
    default="high",
)
def diff(
    terraform_path: Path,
    folder_id: str | None,
    cloud: str | None,
    aws_region: str | None,
    aws_profile: str | None,
    fixture: Path | None,
    config_path: Path | None,
    as_json: bool,
    fail_on: str,
) -> None:
    """Compare Terraform-declared buckets against live or fixture state."""
    config = _load_app_config(config_path).scan
    _apply_scan_overrides(
        config,
        folder_id=folder_id,
        cloud=cloud,
        aws_region=aws_region,
        aws_profile=aws_profile,
    )
    threshold = Severity(fail_on.lower())
    try:
        report = run_scan(
            folder_id=config.folder_id,
            fixture=fixture,
            config=config,
            terraform_path=terraform_path,
        )
    except ScanError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2) from exc

    if as_json:
        click.echo(render_json(_iac_report(report)))
    else:
        render_human(_iac_report(report), console)

    if should_fail(_iac_report(report), threshold):
        raise SystemExit(1)
    raise SystemExit(0)


@main.command()
@click.argument("rule_id")
def explain(rule_id: str) -> None:
    """Show remediation guidance for a rule ID."""
    console.print(explain_rule(rule_id))
    raise SystemExit(0)


@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing .bucket-scanner.toml")
@click.argument("path", default=".", type=click.Path(path_type=Path))
def init(force: bool, path: Path) -> None:
    """Write a starter .bucket-scanner.toml configuration file."""
    target = path / ".bucket-scanner.toml"
    try:
        write_default_config(target, force=force)
    except FileExistsError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise SystemExit(2) from exc
    console.print(f"[green]Wrote[/green] {target}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()
