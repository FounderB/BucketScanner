# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you find a security issue in Bucket Scanner, please **do not** open a public GitHub issue with exploit details.

Contact the maintainer with:

1. Description of the issue
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (optional)

We aim to acknowledge reports within **72 hours**.

## Design principles

- **Metadata by default** — scans use Yandex Cloud APIs for bucket settings; no bulk object exfiltration.
- **Probe is explicit** — `--probe` performs anonymous HTTP reachability checks only; never downloads object bodies.
- **Redaction** — reports sanitize tokens, key material, and sensitive URLs before emit (human, JSON, SARIF).
- **Demo data** — examples use clearly labeled fake credentials and bucket names.

## Out of scope

Bucket Scanner scans **your** cloud configuration with credentials you provide. It is not a SaaS and does not phone home.
