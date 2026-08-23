"""Load offline demo fixtures."""

from __future__ import annotations

import tomllib
from pathlib import Path

from bucket_scanner.models import BucketSnapshot, ServiceAccountKeySnapshot


def load_fixture(path: Path) -> tuple[str, list[BucketSnapshot], list[ServiceAccountKeySnapshot]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    folder_id = data.get("folder_id", "fixture")
    default_cloud = data.get("cloud", "yandex")
    account_bpa = data.get("account_public_access_block")
    buckets: list[BucketSnapshot] = []
    for item in data.get("buckets", []):
        buckets.append(
            BucketSnapshot(
                name=item["name"],
                cloud=item.get("cloud", default_cloud),
                folder_id=folder_id,
                region=item.get("region"),
                acl=item.get("acl", "private"),
                encryption_enabled=bool(item.get("encryption", False)),
                logging_enabled=bool(item.get("logging", False)),
                versioning_enabled=bool(item.get("versioning", False)),
                lifecycle_rules=item.get("lifecycle_rules", []),
                policy=item.get("policy"),
                anonymous_listable=item.get("anonymous_listable"),
                anonymous_readable=item.get("anonymous_readable"),
                block_public_access=item.get("block_public_access"),
                account_public_access_block=item.get("account_public_access_block", account_bpa),
            )
        )

    sa_keys: list[ServiceAccountKeySnapshot] = []
    for item in data.get("service_accounts", {}).get("keys", []):
        sa_keys.append(
            ServiceAccountKeySnapshot(
                sa_id=item["sa_id"],
                key_id=item.get("key_id"),
                age_days=item.get("age_days"),
                roles=item.get("roles", []),
            )
        )
    return folder_id, buckets, sa_keys
