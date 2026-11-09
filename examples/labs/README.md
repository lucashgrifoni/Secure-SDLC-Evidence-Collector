# External lab evidence

This directory documents lab evidence bundles produced by the collector
against a separate set of intentionally vulnerable sample applications
(`01-core-saas-lab` … `07-oss-policy-fixtures-lab`) covering SaaS, identity /
admin, cloud-native, data batch, AI/LLM, regulated-industry, and OSS policy
fixtures.

**That lab corpus is not public.** It lives in a sibling directory on the
maintainer's machine, so the results below are maintainer-local records.
Without the corpus they cannot be reproduced from this repository; the
public, reproducible fixture is
[`examples/sample_release/`](../sample_release/).

Goal: check that the collector behaves consistently when fed a real-world,
untreated evidence set: no planted results, no curated attestations, only
what scanners actually produced.

## What lives here

Only this README is committed. `scripts/scan_all_labs.sh` creates one
directory per lab when it runs, with this shape:

```
examples/labs/
  01-core-saas-lab/
    artifacts/             # generated locally, ignored by Git
      semgrep.sarif        # Semgrep p/security-audit
      trivy.sarif          # Trivy fs vuln+secret+misconfig
      gitleaks.sarif       # Gitleaks --no-git --redact
      sbom.cdx.json        # Syft CycloneDX
    output/                # generated locally, ignored by Git
      bundle.json          # deterministic bundle
      report.md            # human-readable rollup
      summary.html         # stakeholder summary
    logs/                  # generated scanner logs, ignored by Git
  02-identity-admin-lab/  … (same shape)
  …
```

Attestations are intentionally **absent** from each lab — real vuln apps
do not ship release-approval YAMLs, rollback plans, or code-review
metadata. The expected verdict is therefore `not_ready` with an explicit
list of missing critical controls, demonstrating the collector's ability
to surface evidence gaps rather than hide them.

## Baseline summary (historical, recorded 2026-04-24)

This table was recorded with the collector as it was on 2026-04-24, before
later catalog and parser changes. It is kept as a record, not as a current
expectation.

| Lab | Status | Coverage | Met | Partial | Missing |
|---|---|---|---|---|---|
| 01-core-saas-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 02-identity-admin-lab | `not_ready` | 38 | 3 | 3 | 7 |
| 03-cloud-native-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 04-data-batch-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 05-ai-llm-lab | `not_ready` | 29 | 2 | 3 | 8 |
| 06-industry-regulated-lab | `not_ready` | 38 | 3 | 3 | 7 |
| 07-oss-policy-fixtures-lab | `not_ready` | 29 | 2 | 3 | 8 |

Expected gaps across the labs, by criticality in the default catalog:

- **Critical** (these make the verdict `not_ready`): `ORG-CODE-REVIEW
  (code_review)`, `ORG-RELEASE-APPROVAL (release_approval)`,
  `ORG-REL-ROLLBACK (rollback_plan)` and `SSDF-PS.2 (artifact_signature)`,
  plus `SSDF-PS.3 (sbom)` for lab 04.
- **High**: `SSDF-PW.4 (sca_scan)` for labs where the scanners did not cover
  the dependency graph, and `SSDF-PW.8 (test_result)`.

The last recorded pass (2026-05-17) matched the lab rows in
[`docs/traceability.md` §4](../../docs/traceability.md).

## Regenerating

With the lab corpus available:

```bash
LAB_ROOT=/path/to/the/lab/corpus bash scripts/scan_all_labs.sh
```

The script runs Semgrep, Trivy fs, Gitleaks, and Syft on each lab, then
runs `sdlc-evidence` with no attestations to produce a baseline bundle.
Expected runtime: ~5-15 minutes depending on the machine and lab sizes.

Read its output, not only its exit code. A lab directory that is missing
prints `[skip] <lab> missing`, and a collector run that exits non-zero for
any reason prints `collector exited non-zero (expected: not_ready)`; in both
cases the script carries on and still exits `0`.
