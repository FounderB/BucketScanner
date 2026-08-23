# Compliance mappings

Bucket Scanner attaches **compliance tags** to SARIF rules and results for filtering in GitHub Code Scanning and SIEM pipelines.

Tags appear in SARIF `properties.tags` and structured mappings in `properties.compliance`.

## Frameworks

| Prefix | Framework |
|--------|-----------|
| `CIS-*` | CIS Benchmark controls (cloud storage sections) |
| `NIST-*` | NIST 800-53 control families (informative mapping) |
| `SOC2-*` | SOC 2 Trust Services Criteria (informative mapping) |

Mappings are **informative**, not certified compliance attestations. Validate against your auditor's control matrix.

## Example SARIF rule

```json
{
  "id": "acl/public-read",
  "properties": {
    "tags": ["security", "CIS-1.5", "NIST-AC-3", "SOC2-CC6.1"],
    "compliance": {
      "cis": ["1.5"],
      "nist_800_53": ["AC-3"],
      "soc2": ["CC6.1"]
    }
  }
}
```

## Covered rules

See [`src/bucket_scanner/compliance.py`](../src/bucket_scanner/compliance.py) for the full `COMPLIANCE_TAGS` map.

Core coverage:

- Public access (`acl/*`, `probe/*`, cloud BPA rules)
- Encryption, logging, versioning
- IAM key hygiene
- Repo secret patterns
- Misconfig chains (`chain/silent-exfil`, `chain/leaked-credentials-exposure`)

## Usage

```bash
bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml \
  --sarif report.sarif --fail-on high
```

Upload `report.sarif` via GitHub Code Scanning or your SARIF-compatible platform. Filter by tag, e.g. `CIS-1.5` or `NIST-AC-3`.

## Compliance JSON export

Aggregate findings by control tag for GRC dashboards:

```bash
bucket-scanner scan --fixture examples/demo-vulnerable/fixture.toml \
  --compliance-report compliance.json --fail-on high
```

See [`build_compliance_report`](../src/bucket_scanner/compliance.py) output shape: `controls`, `untagged_findings`, `summary.by_control`.

Cross-stack Tracefuse import: [TRACEFUSE.md](TRACEFUSE.md).
