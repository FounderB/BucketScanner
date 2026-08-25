"""Yandex Cloud management API client."""

from __future__ import annotations

from typing import Any

import httpx

STORAGE_API = "https://storage.api.cloud.yandex.net/storage/v1"
IAM_API = "https://iam.api.cloud.yandex.net/iam/v1"
AWS_COMPAT_API = "https://iam.api.cloud.yandex.net/iam/aws-compatibility/v1"
RESOURCE_MANAGER_API = "https://resource-manager.api.cloud.yandex.net/resource-manager/v1"


class ManagementError(RuntimeError):
    """Raised when a Yandex Cloud management API call fails."""


class YcManagementClient:
    def __init__(self, iam_token: str) -> None:
        self._headers = {"Authorization": f"Bearer {iam_token}"}

    def list_buckets(self, folder_id: str) -> list[dict[str, Any]]:
        return self._paginate(
            f"{STORAGE_API}/buckets",
            params={"folderId": folder_id},
            list_key="buckets",
        )

    def list_service_accounts(self, folder_id: str) -> list[dict[str, Any]]:
        return self._paginate(
            f"{IAM_API}/serviceAccounts",
            params={"folderId": folder_id},
            list_key="serviceAccounts",
        )

    def list_access_keys(self, service_account_id: str) -> list[dict[str, Any]]:
        """List AWS-compatible static access keys for Object Storage."""
        return self._paginate(
            f"{AWS_COMPAT_API}/accessKeys",
            params={"serviceAccountId": service_account_id},
            list_key="accessKeys",
        )

    def list_folder_access_bindings(self, folder_id: str) -> list[dict[str, Any]]:
        """List IAM access bindings on a folder (Resource Manager API)."""
        return self._paginate(
            f"{RESOURCE_MANAGER_API}/folders/{folder_id}:listAccessBindings",
            params={},
            list_key="accessBindings",
        )

    def get_bucket(self, name: str, *, view: str = "VIEW_FULL") -> dict[str, Any]:
        """Fetch bucket details including ACL/policy/CORS/website when view=VIEW_FULL."""
        return self._get_json(
            f"{STORAGE_API}/buckets/{name}",
            params={"view": view},
        )

    def create_ephemeral_access_key(
        self,
        *,
        session_name: str = "bucket-scanner",
        duration_seconds: int = 3600,
        subject_id: str | None = None,
        policy: str | None = None,
    ) -> dict[str, Any]:
        """Mint short-lived AWS-compatible credentials from the current IAM token.

        Enables full S3 metadata scans in CI without storing YC_ACCESS_KEY_* secrets.
        """
        body: dict[str, Any] = {
            "sessionName": session_name[:64],
            "duration": f"{max(900, min(duration_seconds, 43200))}s",
        }
        if subject_id:
            body["subjectId"] = subject_id
        if policy:
            body["policy"] = policy
        return self._post_json(f"{AWS_COMPAT_API}/ephemeralAccessKeys", body)

    def ping(self, folder_id: str | None = None) -> bool:
        """Validate IAM token. Prefer folder_id — List serviceAccounts requires it."""
        params: dict[str, Any] = {"pageSize": 1}
        if folder_id:
            params["folderId"] = folder_id
        try:
            response = httpx.get(
                f"{IAM_API}/serviceAccounts",
                params=params,
                headers=self._headers,
                timeout=15.0,
            )
        except httpx.HTTPError:
            return False
        if response.status_code == 200:
            return True
        # Without folderId the API returns 400; treat auth failures as unreachable.
        if folder_id is None and response.status_code == 400:
            # Token reached IAM (bad request for missing folderId), so auth works.
            body = response.text.lower()
            if "folder" in body or "folderid" in body:
                return True
        return False

    def _paginate(
        self,
        url: str,
        *,
        params: dict[str, Any],
        list_key: str,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page_token: str | None = None
        while True:
            query = dict(params)
            if page_token:
                query["pageToken"] = page_token
            data = self._get_json(url, params=query)
            items.extend(data.get(list_key, []))
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        return items

    def _get_json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = httpx.get(
                url,
                params=params,
                headers=self._headers,
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ManagementError(
                f"Yandex Cloud API {exc.response.status_code} for {url}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ManagementError(f"Yandex Cloud API request failed for {url}: {exc}") from exc
        payload = response.json()
        if not isinstance(payload, dict):
            raise ManagementError(f"Unexpected JSON payload from {url}")
        return payload

    def _post_json(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = httpx.post(
                url,
                json=body,
                headers=self._headers,
                timeout=30.0,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ManagementError(
                f"Yandex Cloud API {exc.response.status_code} for {url}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ManagementError(f"Yandex Cloud API request failed for {url}: {exc}") from exc
        payload = response.json()
        if not isinstance(payload, dict):
            raise ManagementError(f"Unexpected JSON payload from {url}")
        return payload
