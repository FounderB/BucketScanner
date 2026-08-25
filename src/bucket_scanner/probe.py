"""Anonymous reachability probes for Object Storage buckets."""

from __future__ import annotations

import httpx

from bucket_scanner.models import BucketSnapshot

YC_STORAGE_HOST = "storage.yandexcloud.net"
YC_WEBSITE_HOST = "website.yandexcloud.net"


def probe_bucket(bucket: BucketSnapshot, *, timeout: float = 10.0) -> BucketSnapshot:
    bucket_url, list_url = _probe_urls(bucket)
    anonymous_readable = False
    anonymous_listable = False
    evidence: dict = {
        "bucket_url": bucket_url,
        "list_url": list_url,
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            head = client.head(bucket_url)
            evidence["head_status"] = head.status_code
            if head.status_code in {200, 206}:
                anonymous_readable = True

            listing = client.get(list_url)
            evidence["list_status"] = listing.status_code
            if listing.status_code == 200 and _listing_looks_public(bucket, listing.text):
                anonymous_listable = True
                # List success ≠ object GET; keep readable only if HEAD already said so
                # or cloud returns object bodies in listing (rare). Do not force readable.

            if bucket.cloud == "yandex" and bucket.website_enabled:
                website_url = f"https://{bucket.name}.{YC_WEBSITE_HOST}/"
                site = client.head(website_url)
                evidence["website_url"] = website_url
                evidence["website_status"] = site.status_code
                if site.status_code in {200, 206}:
                    anonymous_readable = True
                    evidence["website_readable"] = True
    except httpx.HTTPError as exc:
        evidence["error"] = type(exc).__name__
        return bucket.model_copy(update={"probe_evidence": evidence})

    return bucket.model_copy(
        update={
            "anonymous_readable": anonymous_readable,
            "anonymous_listable": anonymous_listable,
            "probe_evidence": evidence,
        }
    )


def _listing_looks_public(bucket: BucketSnapshot, body: str) -> bool:
    text = body or ""
    if bucket.cloud == "azure":
        return "<EnumerationResults" in text or "<Blobs>" in text
    if bucket.cloud == "gcs":
        return '"items"' in text or "<ListBucketResult" in text
    return "<ListBucketResult" in text


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
