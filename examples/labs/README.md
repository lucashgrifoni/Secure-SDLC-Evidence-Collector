# External lab evidence

This directory ships recorded evidence bundles produced by the collector
against the sibling **App vuln - teste** repository
(`01-core-saas-lab` … `07-oss-policy-fixtures-lab`), which is a set of
intentionally vulnerable sample applications covering SaaS, identity /
admin, cloud-native, data batch, AI/LLM, regulated-industry, and OSS
policy fixtures.

Goal: prove, by recorded verdict, that the collector behaves consistently
when fed a **real-world, untreated** evidence set — no planted results,
no curated attestations, only what scanners actually produced.

## What lives here

```
examples/labs/
  01-core-saas-lab/
    artifacts/
      semgrep.sarif        # Semgrep p/security-audit
      trivy.sarif          # Trivy fs vuln+secret+misconfig
      gitleaks.sarif       # Gitleaks --no-git --redact
      sbom.cdx.json        # Syft CycloneDX
    output/
      bundle.json          # deterministic bundle
      report.md            # human-readable rollup
      summary.html         # stakeholder summary
    logs/                  # scanner logs, for forensic review
    README.md              # expected vs. obtained verdict
  02-identity-admin-lab/  … (same shape)
  …
```

Attestations are intentionally **absent** from each lab — real vuln apps
do not ship release-approval YAMLs, rollback plans, or code-review
metadata. The expected verdict is therefore `not_ready` with an explicit
list of missing critical controls, demonstrating the collector's ability
to surface evidence gaps rather than hide them.

## Baseline summary (recorded 2026-04-24)

| Lab | Status | Coverage | Met | Partial | Missing |
|---|---|---|---|---|---|
| 01-core-saas-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 02-identity-admin-lab | `not_ready` | 38 | 3 | 3 | 7 |
| 03-cloud-native-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 04-data-batch-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 05-ai-llm-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 06-industry-regulated-lab | `not_ready` | 38 | 3 | 3 | 7 |
| 07-oss-policy-fixtures-lab | `not_ready` | 29 | 2 | 3 | 8 |

Expected missing critical controls across all labs:
`SSDF-PW.4 (sca_scan)` — for labs where Syft/Trivy's SBOM did not cover
the dependency graph; `SSDF-PW.8 (test_result)`, `ORG-CODE-REVIEW
(code_review)`, `ORG-RELEASE-APPROVAL (release_approval)`,
`ORG-REL-ROLLBACK (rollback_plan)`, `SSDF-PS.2 (artifact_signature)`.

All seven results match the expected verdicts documented in
`docs/traceability.md §3–§4`.

## Regenerating

```bash
bash scripts/scan_all_labs.sh
```

The script runs Semgrep, Trivy fs, Gitleaks, and Syft on each lab, then
runs `sdlc-evidence` with no attestations to produce a baseline bundle.
Expected runtime: ~5-15 minutes depending on the machine and lab sizes.
