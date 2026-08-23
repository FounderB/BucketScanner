"""Yandex Cloud management API client."""

from __future__ import annotations

from typing import Any

import httpx

STORAGE_API = "https://storage.api.cloud.yandex.net/storage/v1"
IAM_API = "https://iam.api.cloud.yandex.net/iam/v1"


class YcManagementClient:
    def __init__(self, iam_token: str) -> None:
        self._headers = {"Authorization": f"Bearer {iam_token}"}

    def list_buckets(self, folder_id: str) -> list[dict[str, Any]]:
        response = httpx.get(
            f"{STORAGE_API}/buckets",
            params={"folderId": folder_id},
            headers=self._headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("buckets", [])

    def list_service_accounts(self, folder_id: str) -> list[dict[str, Any]]:
        response = httpx.get(
            f"{IAM_API}/serviceAccounts",
            params={"folderId": folder_id},
            headers=self._headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("serviceAccounts", [])

    def list_access_keys(self, service_account_id: str) -> list[dict[str, Any]]:
        response = httpx.get(
            f"{IAM_API}/keys",
            params={"serviceAccountId": service_account_id},
            headers=self._headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("keys", [])

    def list_folder_access_bindings(self, folder_id: str) -> list[dict[str, Any]]:
        response = httpx.get(
            f"{IAM_API}/folders/{folder_id}:listAccessBindings",
            headers=self._headers,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json().get("accessBindings", [])

    def ping(self) -> bool:
        response = httpx.get(
            f"{IAM_API}/serviceAccounts",
            params={"pageSize": 1},
            headers=self._headers,
            timeout=15.0,
        )
        return response.status_code == 200
