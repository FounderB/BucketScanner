# Security audit log

Manual and automated checks run against Bucket Scanner **v0.11.0**.

## Automated (CI / local `make audit`)

| Tool | Scope | Result |
|------|-------|--------|
| **ruff** | lint (E, F, I, UP, B) | pass |
| **pytest** | 110+ tests, cov ≥ 75% | pass (~84%) |
| **bandit** | Python SAST on `src/` | pass (0 issues) |
| **pip-audit** | dependency CVEs | pass (no known vulns) |

## Security fixes in v0.11.0

| Area | Change |
|------|--------|
| **YC credentials** | Removed `AWS_*` env fallback when resolving Yandex keys — prevents accidental cross-cloud key use |
| **Webhook notify** | Reject non-HTTP(S) URLs (`file://`, etc.) |
| **Probe** | `follow_redirects=False` on anonymous HEAD/GET |
| **Baseline load** | 10 MB max JSON size (DoS guard) |
| **IAM scan** | Catch `ClientError`/`BotoCoreError` instead of bare `Exception` |

## Manual review notes

| Topic | Status |
|-------|--------|
| Secrets in repo scan | Patterns only; evidence redacted; skips binaries > 1 MB |
| SARIF / JSON output | Findings redacted via `redact_finding()` |
| Serve bind | User-controlled addr; `0.0.0.0` documented with `# nosec B104` |
| Terraform path | Read-only file parse; no `eval` / no shell |
| Telegram / webhook | User-supplied endpoints; HTTPS recommended |
| Demo fixtures | FAKE/EXAMPLE values only under `examples/` |

## Residual risks / roadmap

- Azure live scan requires optional `bucket-scanner[azure]` — larger dependency tree; pin versions in CI
- Webhook POST sends finding summaries to user-configured URL — operators must trust target
- `--probe` generates outbound HTTP to bucket endpoints (expected behaviour)
- PyPI publish pending — install from source or GitHub Action today

Re-run locally:

```bash
make audit
make test
```
