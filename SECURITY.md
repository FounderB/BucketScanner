# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x | Yes |
| 0.10.x – 0.15.x | Best effort |
| < 0.10 | No |

## Reporting a vulnerability

If you find a security issue in Bucket Scanner, please **do not** open a public GitHub issue with exploit details.

Contact the maintainer with:

1. Description of the issue
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (optional)

We aim to acknowledge reports within **72 hours**.

## Design principles

- **Metadata by default** — scans use cloud APIs for bucket settings; no bulk object exfiltration.
- **Probe is explicit** — `--probe` performs anonymous HTTP reachability checks only; no redirect follow; never downloads object bodies.
- **Redaction** — reports sanitize tokens, key material, and sensitive URLs before emit (human, JSON, SARIF).
- **Credential isolation** — Yandex credentials resolve from `YC_*` env vars only (not `AWS_*` aliases).
- **Webhook safety** — notification URLs must use `http` or `https` schemes.
- **Demo data** — examples use clearly labeled fake credentials and bucket names.

See [AUDIT.md](docs/AUDIT.md) for the latest automated audit results.

## Out of scope

Bucket Scanner scans **your** cloud configuration with credentials you provide. It is not a SaaS and does not phone home.
