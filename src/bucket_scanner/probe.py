"""Anonymous reachability probes for Object Storage buckets."""

from __future__ import annotations

import httpx

from bucket_scanner.models import BucketSnapshot

YC_STORAGE_HOST = "storage.yandexcloud.net"


def probe_bucket(bucket: BucketSnapshot, *, timeout: float = 10.0) -> BucketSnapshot:
    bucket_url, list_url = _probe_urls(bucket)
    anonymous_readable = False
    anonymous_listable = False

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        head = client.head(bucket_url)
        if head.status_code in {200, 206}:
            anonymous_readable = True

        listing = client.get(list_url)
        if listing.status_code == 200 and "<ListBucketResult" in listing.text:
            anonymous_listable = True
            anonymous_readable = True

    return bucket.model_copy(
        update={
            "anonymous_readable": anonymous_readable,
            "anonymous_listable": anonymous_listable,
        }
    )


def _probe_urls(bucket: BucketSnapshot) -> tuple[str, str]:
    if bucket.cloud == "aws":
        region = bucket.region or "us-east-1"
        if region == "us-east-1":
            host = f"{bucket.name}.s3.amazonaws.com"
        else:
            host = f"{bucket.name}.s3.{region}.amazonaws.com"
        bucket_url = f"https://{host}/"
        list_url = f"{bucket_url}?max-keys=1"
    elif bucket.cloud == "azure":
        account = bucket.tags.get("storage_account", bucket.name)
        bucket_url = f"https://{account}.blob.core.windows.net/{bucket.name}"
        list_url = f"{bucket_url}?restype=container&comp=list"
    elif bucket.cloud == "gcs":
        bucket_url = f"https://storage.googleapis.com/{bucket.name}/"
        list_url = f"{bucket_url}?maxResults=1"
    else:
        bucket_url = f"https://{bucket.name}.{YC_STORAGE_HOST}/"
        list_url = f"{bucket_url}?max-keys=1"
    return bucket_url, list_url
