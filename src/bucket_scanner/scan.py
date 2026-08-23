"""Scan orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from bucket_scanner import __version__
from bucket_scanner.auth import Credentials, resolve_credentials
from bucket_scanner.aws.iam import list_iam_access_keys
from bucket_scanner.aws.s3 import (
    build_aws_s3_client,
    get_account_public_access_block,
    list_bucket_names,
    resolve_account_id,
    resolve_bucket_region,
    snapshot_aws_bucket,
)
from bucket_scanner.chains import compose_chains
from bucket_scanner.checks import (
    apply_overrides,
    check_bucket,
    check_service_accounts,
    redact_finding,
)
from bucket_scanner.cloud import CloudProvider
from bucket_scanner.config import ScanConfig
from bucket_scanner.diff import diff_terraform
from bucket_scanner.fixture import load_fixture
from bucket_scanner.models import (
    SEVERITY_WEIGHT,
    BucketSnapshot,
    ScanReport,
    ScanSummary,
    ServiceAccountKeySnapshot,
    Severity,
    severity_at_least,
)
from bucket_scanner.probe import probe_bucket
from bucket_scanner.secrets import scan_repo
from bucket_scanner.tracefuse import load_tracefuse_report
from bucket_scanner.yc.management import YcManagementClient
from bucket_scanner.yc.s3 import build_s3_client, snapshot_yandex_bucket


class ScanError(RuntimeError):
    pass


def _key_age_days(created_at: str | None) -> int | None:
    if not created_at:
        return None
    created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    return (datetime.now(tz=UTC) - created).days


def _roles_for_subject(bindings: list[dict], subject_id: str) -> list[str]:
    return [
        binding["roleId"]
        for binding in bindings
        if binding.get("subject", {}).get("id") == subject_id
    ]


def _collect_yandex_data(
    folder_id: str,
    credentials: Credentials,
    *,
    probe: bool,
    ignore: set[str],
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot]]:
    if not credentials.iam_token:
        raise ScanError("IAM token is required to list buckets in a folder.")

    management = YcManagementClient(credentials.iam_token)
    bucket_rows = management.list_buckets(folder_id)
    bindings = management.list_folder_access_bindings(folder_id)
    has_s3_keys = bool(credentials.access_key_id and credentials.secret_access_key)

    buckets: list[BucketSnapshot] = []
    if has_s3_keys:
        s3 = build_s3_client(credentials)
        for row in bucket_rows:
            name = row["name"]
            if name in ignore:
                continue
            snapshot = snapshot_yandex_bucket(s3, name, folder_id=folder_id)
            if probe:
                snapshot = probe_bucket(snapshot)
            buckets.append(snapshot)
    else:
        for row in bucket_rows:
            name = row["name"]
            if name in ignore:
                continue
            snapshot = BucketSnapshot(
                name=name,
                cloud=CloudProvider.YANDEX.value,
                folder_id=folder_id,
                metadata_known=False,
            )
            if probe:
                snapshot = probe_bucket(snapshot)
            buckets.append(snapshot)

    sa_keys: list[ServiceAccountKeySnapshot] = []
    for sa in management.list_service_accounts(folder_id):
        roles = _roles_for_subject(bindings, sa["id"])
        for key in management.list_access_keys(sa["id"]):
            sa_keys.append(
                ServiceAccountKeySnapshot(
                    sa_id=sa["id"],
                    key_id=key.get("id"),
                    age_days=_key_age_days(key.get("createdAt")),
                    roles=roles,
                )
            )
    return buckets, sa_keys


def _collect_aws_data(
    credentials: Credentials,
    *,
    probe: bool,
    ignore: set[str],
    scan_iam: bool,
    resolve_regions: bool,
) -> tuple[list[BucketSnapshot], list[ServiceAccountKeySnapshot], str]:
    default_region = credentials.region or "us-east-1"
    listing_client = build_aws_s3_client(credentials, region=default_region)
    account_id = resolve_account_id(credentials)
    account_bpa = get_account_public_access_block(credentials, account_id)
    client_cache: dict[str, object] = {default_region: listing_client}

    def client_for_region(region: str):
        if region not in client_cache:
            client_cache[region] = build_aws_s3_client(credentials, region=region)
        return client_cache[region]

    buckets: list[BucketSnapshot] = []
    for name in list_bucket_names(listing_client):
        if name in ignore:
            continue
        bucket_region = default_region
        if resolve_regions:
            bucket_region = resolve_bucket_region(
                listing_client,
                name,
                default=default_region,
            )
        snapshot = snapshot_aws_bucket(
            client_for_region(bucket_region),
            name,
            account_id=account_id,
            region=bucket_region,
            account_public_access_block=account_bpa,
        )
        if probe:
            snapshot = probe_bucket(snapshot)
        buckets.append(snapshot)

    sa_keys: list[ServiceAccountKeySnapshot] = []
    if scan_iam:
        try:
            sa_keys = list_iam_access_keys(credentials)
        except Exception:
            sa_keys = []
    return buckets, sa_keys, account_id


def resolve_folder_ids(config: ScanConfig, folder_id: str | None = None) -> list[str]:
    if folder_id:
        return [folder_id]
    if config.folder_ids:
        return list(config.folder_ids)
    if config.folder_id:
        return [config.folder_id]
    return []


def _finalize_report(
    *,
    buckets: list[BucketSnapshot],
    sa_keys: list[ServiceAccountKeySnapshot],
    folder: str,
    scope_ids: list[str],
    report_cloud: str,
    method: str,
    probe: bool,
    config: ScanConfig,
    terraform_path: Path | None,
    repo_path: Path | None,
    tracefuse_report: Path | None,
) -> ScanReport:
    findings = []
    for bucket in buckets:
        findings.extend(check_bucket(bucket))
    findings.extend(check_service_accounts(sa_keys, key_age_days=config.key_age_days))
    if terraform_path:
        findings.extend(diff_terraform(terraform_path, buckets))
    if repo_path:
        findings.extend(scan_repo(repo_path, cloud=config.cloud))
    if tracefuse_report:
        findings.extend(load_tracefuse_report(tracefuse_report))
    findings = apply_overrides(findings, config.severity_overrides)
    findings = [redact_finding(item) for item in findings]
    chains = compose_chains(buckets, findings)
    summary = _build_summary(findings, chains, buckets_scanned=len(buckets))
    return ScanReport(
        version=__version__,
        cloud=report_cloud,
        folder_id=folder,
        scope_ids=scope_ids,
        probe_enabled=probe,
        buckets=buckets,
        findings=findings,
        chains=chains,
        summary=summary,
        method=method,
    )


def run_scan(
    *,
    folder_id: str | None,
    fixture: Path | None,
    config: ScanConfig,
    terraform_path: Path | None = None,
    repo_path: Path | None = None,
    tracefuse_report: Path | None = None,
) -> ScanReport:
    probe = config.probe
    ignore = config.ignore_buckets
    tf_path = terraform_path or config.terraform_path
    repo = repo_path or config.repo_path
    tracefuse = tracefuse_report or config.tracefuse_report
    cloud = config.cloud

    if fixture:
        resolved_folder, buckets, sa_keys = load_fixture(fixture)
        folder = folder_id or resolved_folder
        if probe:
            buckets = [probe_bucket(bucket) for bucket in buckets]
        method = "fixture"
        report_cloud = buckets[0].cloud if buckets else cloud.value
    elif cloud == CloudProvider.AWS:
        credentials = resolve_credentials(
            cloud=CloudProvider.AWS,
            region=config.aws_region,
            profile=config.aws_profile,
        )
        buckets, sa_keys, account_id = _collect_aws_data(
            credentials,
            probe=probe,
            ignore=ignore,
            scan_iam=config.aws_scan_iam,
            resolve_regions=config.aws_resolve_regions,
        )
        folder = folder_id or account_id
        method = "live"
        report_cloud = CloudProvider.AWS.value
    elif cloud == CloudProvider.AZURE:
        raise ScanError(
            "Azure Blob live scan is not implemented yet. Use --fixture for offline demos."
        )
    else:
        folder_ids = resolve_folder_ids(config, folder_id)
        if not folder_ids:
            raise ScanError("Provide --folder-id, folder_ids in config, or --fixture.")
        credentials = resolve_credentials(cloud=CloudProvider.YANDEX)
        all_buckets: list[BucketSnapshot] = []
        all_sa_keys: list[ServiceAccountKeySnapshot] = []
        for fid in folder_ids:
            buckets_part, keys_part = _collect_yandex_data(
                fid,
                credentials,
                probe=probe,
                ignore=ignore,
            )
            all_buckets.extend(buckets_part)
            all_sa_keys.extend(keys_part)
        folder = ",".join(folder_ids)
        method = "live"
        report_cloud = CloudProvider.YANDEX.value
        return _finalize_report(
            buckets=all_buckets,
            sa_keys=all_sa_keys,
            folder=folder,
            scope_ids=folder_ids,
            report_cloud=report_cloud,
            method=method,
            probe=probe,
            config=config,
            terraform_path=tf_path,
            repo_path=repo,
            tracefuse_report=tracefuse,
        )

    findings = []
    for bucket in buckets:
        findings.extend(check_bucket(bucket))
    findings.extend(check_service_accounts(sa_keys, key_age_days=config.key_age_days))
    if tf_path:
        findings.extend(diff_terraform(tf_path, buckets))
    if repo:
        findings.extend(scan_repo(repo, cloud=cloud))
    if tracefuse:
        findings.extend(load_tracefuse_report(tracefuse))
    findings = apply_overrides(findings, config.severity_overrides)
    findings = [redact_finding(item) for item in findings]
    chains = compose_chains(buckets, findings)

    scope_ids = [folder] if folder else []
    summary = _build_summary(findings, chains, buckets_scanned=len(buckets))
    return ScanReport(
        version=__version__,
        cloud=report_cloud,
        folder_id=folder,
        scope_ids=scope_ids,
        probe_enabled=probe,
        buckets=buckets,
        findings=findings,
        chains=chains,
        summary=summary,
        method=method,
    )


def _build_summary(findings, chains, *, buckets_scanned: int) -> ScanSummary:
    summary = ScanSummary(buckets_scanned=buckets_scanned, chains=len(chains))
    score = 0
    for finding in findings:
        summary.total += 1
        score += SEVERITY_WEIGHT[finding.severity]
        setattr(summary, finding.severity.value, getattr(summary, finding.severity.value) + 1)
    summary.score = min(score, 100)
    return summary


def should_fail(report: ScanReport, threshold: Severity) -> bool:
    for finding in report.findings:
        if severity_at_least(finding.severity, threshold):
            return True
    for chain in report.chains:
        if severity_at_least(chain.severity, threshold):
            return True
    return False
