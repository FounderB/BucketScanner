"""Cloud scope label helpers for reports and notifications."""


def scope_label_for_cloud(cloud: str) -> str:
    return {"aws": "account", "azure": "subscription", "gcs": "project"}.get(cloud, "folder")
