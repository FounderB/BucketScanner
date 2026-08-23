"""Rule remediation catalog."""

from __future__ import annotations

RULES: dict[str, dict[str, str]] = {
    "acl/public-read": {
        "title": "Public read ACL",
        "why": "Anyone on the internet can read objects if the ACL or policy allows it.",
        "fix": "Set ACL to private. Use pre-signed URLs or authenticated CDN origins.",
    },
    "acl/public-read-write": {
        "title": "Public read/write ACL",
        "why": "Anonymous users can upload, modify, or delete objects.",
        "fix": "Immediately restrict ACL/policy, rotate keys, and audit object integrity.",
    },
    "policy/overly-permissive": {
        "title": "Overly permissive bucket policy",
        "why": "Principal='*' bypasses intent set in Terraform or console labels.",
        "fix": "Scope Principal to specific service accounts or federated identities.",
    },
    "encryption/disabled": {
        "title": "Encryption disabled",
        "why": "Objects at rest rely on platform defaults only; compliance gaps remain.",
        "fix": "Enable default SSE on the bucket.",
    },
    "logging/disabled": {
        "title": "Access logging disabled",
        "why": "You cannot reconstruct who accessed or exfiltrated data after an incident.",
        "fix": "Enable access logging to a dedicated, locked-down audit bucket.",
    },
    "versioning/disabled": {
        "title": "Versioning disabled",
        "why": "Ransomware or accidental deletes are irreversible.",
        "fix": "Enable versioning on production and backup buckets.",
    },
    "lifecycle/aggressive-expiration": {
        "title": "Aggressive lifecycle expiration",
        "why": "Short retention can destroy evidence or backups earlier than policy expects.",
        "fix": "Align lifecycle rules with backup and compliance retention targets.",
    },
    "iam/stale-static-key": {
        "title": "Stale static key",
        "why": "Long-lived keys widen the blast radius when leaked.",
        "fix": "Rotate keys every 90 days; prefer IAM tokens for automation.",
    },
    "iam/over-privileged-sa": {
        "title": "Over-privileged service account",
        "why": "storage.admin on a scanner or app SA exposes every bucket in the folder.",
        "fix": "Use storage.viewer for scans and scoped editor only where writes are required.",
    },
    "probe/anonymous-list": {
        "title": "Anonymous listing confirmed",
        "why": "Probe mode proved ListObjects works without credentials.",
        "fix": "Remove public grants and re-run bucket-scanner scan --probe.",
    },
    "probe/anonymous-read-confirmed": {
        "title": "Declared vs real mismatch",
        "why": "ACL says private but anonymous requests succeed — policy or CDN origin leak.",
        "fix": "Inspect bucket policy, public access blocks, and CDN origin configuration.",
    },
    "iac/acl-drift": {
        "title": "Terraform ACL drift",
        "why": "Infrastructure code says one thing; live bucket ACL says another.",
        "fix": "Run terraform plan/apply or fix live ACL to match declared intent.",
    },
    "iac/shadow-bucket": {
        "title": "Shadow bucket",
        "why": "Live bucket exists outside Terraform — classic shadow IT / orphan resource.",
        "fix": "Import into Terraform or decommission if unused.",
    },
    "iac/ghost-bucket": {
        "title": "Ghost bucket",
        "why": "Terraform declares a bucket that does not exist live — state drift.",
        "fix": "Apply Terraform or remove stale resource block.",
    },
    "tags/missing-env": {
        "title": "Missing environment tag",
        "why": "Prod-like names without env tags make blast-radius and ownership unclear.",
        "fix": "Add environment, owner, and data-class tags to every prod bucket.",
    },
    "metadata/limited": {
        "title": "Limited metadata scan",
        "why": "Without S3 static keys only inventory and probe checks run.",
        "fix": "Provide YC_ACCESS_KEY_ID and YC_SECRET_ACCESS_KEY for full checks.",
    },
    "aws/block-public-access-incomplete": {
        "title": "S3 Block Public Access incomplete",
        "why": "Partial BPA leaves paths for ACL or policy to expose objects publicly.",
        "fix": "Enable all four bucket-level Block Public Access settings in AWS.",
    },
    "aws/account-public-access-incomplete": {
        "title": "Account Block Public Access incomplete",
        "why": "Account-level gaps allow new or updated buckets to become public.",
        "fix": "Enable account-level S3 Block Public Access for the AWS account.",
    },
    "chain/leaked-credentials-exposure": {
        "title": "Leaked credentials + public buckets",
        "why": "Repo secrets plus public storage = immediate compromise path.",
        "fix": "Rotate all YC keys, remove secrets from git history, close public access.",
    },
    "secrets/yc-env-var": {
        "title": "YC credential in repo",
        "why": "Environment files in git leak keys to anyone with repo access.",
        "fix": "Move to CI secrets manager and rotate exposed credentials.",
    },
    "secrets/yc-static-key": {
        "title": "YC static key in repo",
        "why": "Static keys grant durable API access until rotated.",
        "fix": "Delete key in YC console, rotate, and use short-lived IAM tokens.",
    },
    "secrets/aws-env-var": {
        "title": "AWS credential in repo",
        "why": "AWS keys in git grant durable cloud access until rotated.",
        "fix": "Revoke the key in IAM, rotate, and store secrets in a vault or CI secrets.",
    },
    "secrets/aws-access-key-id": {
        "title": "AWS access key ID in repo",
        "why": "AKIA… patterns often pair with secret keys elsewhere in the repo.",
        "fix": "Revoke and rotate IAM access keys; scan git history for paired secrets.",
    },
    "chain/silent-exfil": {
        "title": "Silent exfil chain",
        "why": "Public exposure + no logs + no versioning = undetected, irreversible data loss.",
        "fix": (
            "Close public access first, then enable logging and versioning "
            "before closing ticket."
        ),
    },
}


def explain_rule(rule_id: str) -> str:
    data = RULES.get(rule_id)
    if not data:
        return f"No documentation found for rule '{rule_id}'."
    return (
        f"[bold]{data['title']}[/bold] (`{rule_id}`)\n\n"
        f"[cyan]Why it matters[/cyan]\n{data['why']}\n\n"
        f"[green]Fix[/green]\n{data['fix']}"
    )
