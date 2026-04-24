# Sample release fixture

Realistic release fixture used by the integration tests, the
`make run-example` target, and the README quick-start. Drives the
following evidence set through the collector:

| File | Evidence type | Primary control(s) |
|------|---------------|--------------------|
| `artifacts/semgrep.sarif` | `sast_scan` | `SSDF-PW.7`, `SAMM-VERIF-ST-1` |
| `artifacts/trivy.sarif` | `sca_scan` | `SSDF-PW.4`, `SAMM-VERIF-ST-1` (rec.) |
| `artifacts/gitleaks.sarif` | `secrets_scan` | `ORG-SECRETS-SCAN` |
| `artifacts/sbom.cdx.json` | `sbom` | `SSDF-PS.3`, `SAMM-IMPL-SB-2` |
| `artifacts/junit.xml` | `test_result` | `SSDF-PW.8` |
| `artifacts/zap-baseline.json` | `dast_scan` | `SAMM-VERIF-ST-1` (rec.) |
| `attestations/code_review.yaml` | `code_review` | `ORG-CODE-REVIEW` |
| `attestations/pr_metadata.yaml` | `pr_metadata` | `ORG-CODE-REVIEW` (rec.) |
| `attestations/threat_model.yaml` | `threat_model` | `SSDF-PW.1`, `SAMM-DESIGN-TA-1` |
| `attestations/release_approval.yaml` | `release_approval` | `ORG-RELEASE-APPROVAL` |
| `attestations/rollback_plan.yaml` | `rollback_plan` | `ORG-REL-ROLLBACK` |
| `attestations/artifact_signature.yaml` | `artifact_signature` | `SSDF-PS.2`, `SAMM-IMPL-SB-2` (rec.) |
| `attestations/artifact_attestation.yaml` | `artifact_attestation` | `SSDF-PS.2` (rec.), `SAMM-IMPL-SB-2` (rec.) |

Run with:

```bash
python -m evidence_collector.cli.main run \
  --application payments-api \
  --repository acme/payments-api \
  --release-id 2026.04.10 \
  --commit-sha abcdef1234567890 \
  --branch main \
  --artifacts-dir examples/sample_release/artifacts \
  --attestations-dir examples/sample_release/attestations \
  --output-dir output/sample_release
```

Expected verdict: `release_status = ready`, all controls met, bundle
and reports written to `output/sample_release/`.
