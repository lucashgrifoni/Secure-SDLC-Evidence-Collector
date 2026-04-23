# Sample release fixture

Realistic release fixture used by the CLI `run-example` target, README, and
tests. Drives the following evidence set through the collector:

| File | Evidence type | Control(s) |
|------|---------------|------------|
| `artifacts/semgrep.sarif` | `sast_scan` | `SSDF-PW.7` |
| `artifacts/trivy.sarif` | `sca_scan` | `SSDF-PW.4` |
| `artifacts/gitleaks.sarif` | `secrets_scan` | `ORG-SECRETS-SCAN` |
| `artifacts/sbom.cdx.json` | `sbom` | `SSDF-PS.3` |
| `artifacts/junit.xml` | `test_result` | `SSDF-PW.8` |
| `attestations/code_review.yaml` | `code_review` | `ORG-CODE-REVIEW` |
| `attestations/threat_model.yaml` | `threat_model` | `SSDF-PW.1` |
| `attestations/release_approval.yaml` | `release_approval` | `ORG-RELEASE-APPROVAL` |
| `attestations/rollback_plan.yaml` | `rollback_plan` | `ORG-REL-ROLLBACK` |
| `attestations/artifact_signature.yaml` | `artifact_signature` | `SSDF-PS.2` |

Run with:

```bash
python -m evidence_collector.cli.main run \
  --application payments-api \
  --repository acme/payments-api \
  --release-id 2026.04.10 \
  --commit-sha abc123def456 \
  --branch main \
  --artifacts-dir examples/sample_release/artifacts \
  --attestations-dir examples/sample_release/attestations \
  --output-dir output/sample_release
```
