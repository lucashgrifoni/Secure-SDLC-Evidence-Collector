# Secure SDLC Evidence Report

**Bundle ID:** `bundle-20260517-secure-sdlc-evidence-collector-v1.1.0-49a13cb9`
**Bundle version:** 1.0.0
**Generated at:** 2026-05-17T16:59:59.147344+00:00

## Application

| Field | Value |
|-------|-------|
| Name | `secure-sdlc-evidence-collector` |
| Repository | `lucashgrifoni/Secure-SDLC-Evidence-Collector` |
| Environment | production |
| Owner team | - |

## Release

| Field | Value |
|-------|-------|
| Release ID | `v1.1.0` |
| Commit SHA | `17dede200000000000000000000000000000000a` |
| Branch | `main` |
| Pipeline run | - |
| Build ID | - |
| Artifact digest | `-` |
| Tag | - |

## Verdict

- **Release status:** `ready`
- **Evidence coverage score:** 100/100
- **Confidence score:** 54/100
- **Controls:** 13 met · 0 partial · 0 missing · 0 waived · 0 n/a
- **Missing critical evidence:** none

## Control evaluations

| Control | Framework | Status | Criticality | Confidence | Evidence refs |
|---------|-----------|--------|-------------|------------|---------------|
| `SSDF-PW.7` | NIST_SSDF | **met** | high | high | sast-68eceb7572cf |
| `SSDF-PW.4` | NIST_SSDF | **met** | high | high | sca-9d7b0348e1cd |
| `ORG-SECRETS-SCAN` | ORG_INTERNAL | **met** | high | high | secrets-229bf1391f3d |
| `SSDF-PS.3` | NIST_SSDF | **met** | critical | low | sbom-ac2b408199f3, att-cc948cb8a6a4, att-35354bda8818 |
| `SSDF-PW.8` | NIST_SSDF | **met** | high | high | test-1168c2acaf55 |
| `ORG-CODE-REVIEW` | ORG_INTERNAL | **met** | critical | low | att-fcee80cf86da, att-eb11de699a36 |
| `SSDF-PW.1` | NIST_SSDF | **met** | medium | low | att-59a2382eb18a |
| `ORG-RELEASE-APPROVAL` | ORG_INTERNAL | **met** | critical | low | att-f3bd336bf424 |
| `ORG-REL-ROLLBACK` | ORG_INTERNAL | **met** | critical | low | att-6a5b1ef749bc |
| `SSDF-PS.2` | NIST_SSDF | **met** | critical | low | att-35354bda8818, att-cc948cb8a6a4 |
| `SAMM-DESIGN-TA-1` | OWASP_SAMM | **met** | medium | low | att-59a2382eb18a |
| `SAMM-IMPL-SB-2` | OWASP_SAMM | **met** | high | low | sbom-ac2b408199f3, att-35354bda8818, att-cc948cb8a6a4 |
| `SAMM-VERIF-ST-1` | OWASP_SAMM | **met** | high | low | sast-68eceb7572cf, sca-9d7b0348e1cd, att-db21182f1d7e |

### Rationales

- **`SSDF-PW.7` — Review and/or analyze human-readable code (SAST)**
  Control SSDF-PW.7 is met by evidence ['sast-68eceb7572cf'].
- **`SSDF-PW.4` — Reuse existing, well-secured software (SCA)**
  Control SSDF-PW.4 is met by evidence ['sca-9d7b0348e1cd'].
- **`ORG-SECRETS-SCAN` — Repository-wide secrets scanning**
  Control ORG-SECRETS-SCAN is met by evidence ['secrets-229bf1391f3d'].
- **`SSDF-PS.3` — Archive and protect each software release (SBOM)**
  Control SSDF-PS.3 is met by evidence ['sbom-ac2b408199f3', 'att-cc948cb8a6a4', 'att-35354bda8818'].
- **`SSDF-PW.8` — Test executable code to identify vulnerabilities**
  Control SSDF-PW.8 is met by evidence ['test-1168c2acaf55'].
- **`ORG-CODE-REVIEW` — Code review by eligible reviewers**
  Control ORG-CODE-REVIEW is met by evidence ['att-fcee80cf86da', 'att-eb11de699a36'].
- **`SSDF-PW.1` — Design software to meet security requirements (threat model)**
  Control SSDF-PW.1 is met by evidence ['att-59a2382eb18a'].
- **`ORG-RELEASE-APPROVAL` — Formal release approval**
  Control ORG-RELEASE-APPROVAL is met by evidence ['att-f3bd336bf424'].
- **`ORG-REL-ROLLBACK` — Rollback plan exists and was approved**
  Control ORG-REL-ROLLBACK is met by evidence ['att-6a5b1ef749bc'].
- **`SSDF-PS.2` — Provide a mechanism to verify software release integrity**
  Control SSDF-PS.2 is met by evidence ['att-35354bda8818', 'att-cc948cb8a6a4'].
- **`SAMM-DESIGN-TA-1` — Threat Assessment (Design / Threat Assessment 1)**
  Control SAMM-DESIGN-TA-1 is met by evidence ['att-59a2382eb18a'].
- **`SAMM-IMPL-SB-2` — Secure Build (Implementation / Secure Build 2)**
  Control SAMM-IMPL-SB-2 is met by evidence ['sbom-ac2b408199f3', 'att-35354bda8818', 'att-cc948cb8a6a4'].
- **`SAMM-VERIF-ST-1` — Security Testing (Verification / Security Testing 1)**
  Control SAMM-VERIF-ST-1 is met by evidence ['sast-68eceb7572cf', 'sca-9d7b0348e1cd', 'att-db21182f1d7e'].


## Gaps

No gaps detected.

## Evidence inventory

| ID | Type | Status | Confidence | Producer | Subject |
|----|------|--------|------------|----------|---------|
| `sast-68eceb7572cf` | sast_scan | passed | high | Bandit | `17dede200000000000000000000000000000000a` |
| `secrets-229bf1391f3d` | secrets_scan | passed | high | gitleaks | `17dede200000000000000000000000000000000a` |
| `test-1168c2acaf55` | test_result | passed | high | pytest tests | `17dede200000000000000000000000000000000a` |
| `sca-9d7b0348e1cd` | sca_scan | passed | high | pip-audit | `17dede200000000000000000000000000000000a` |
| `sbom-ac2b408199f3` | sbom | generated | high | cyclonedx | `secure-sdlc-evidence-collector@0.1.0` |
| `att-cc948cb8a6a4` | artifact_attestation | passed | medium | build-provenance-manual | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-35354bda8818` | artifact_signature | passed | medium | git-tag-signature | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-fcee80cf86da` | code_review | passed | medium | solo-maintainer-review | `PR-0-initial-mvp` |
| `att-db21182f1d7e` | dast_scan | passed | low | appsec-review | `secure-sdlc-evidence-collector` |
| `att-eb11de699a36` | pr_metadata | passed | medium | local-git-export | `PR-0-initial-mvp` |
| `att-f3bd336bf424` | release_approval | passed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-6a5b1ef749bc` | rollback_plan | passed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-59a2382eb18a` | threat_model | completed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector` |

### `sast-68eceb7572cf` — sast_scan

- **Source:** Bandit (sarif) · version 1.9.4- **Producer:** Bandit
- **Subject:** `17dede200000000000000000000000000000000a` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** Bandit reported 0 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=0 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\bandit.sarif` (sha256:bb9ad4a5c50d13a0c8a184c6d406202b6e3ea23199a15ebf3514dc83c13733eb)

### `secrets-229bf1391f3d` — secrets_scan

- **Source:** gitleaks (sarif) · version v8.0.0- **Producer:** gitleaks
- **Subject:** `17dede200000000000000000000000000000000a` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** gitleaks reported 0 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=0 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\gitleaks.sarif` (sha256:8c99bf9ee1e5399d1160091d33c085c3c82388dbc570206841c3f3716597a6a5)

### `test-1168c2acaf55` — test_result

- **Source:** junit (junit-xml)- **Producer:** pytest tests
- **Subject:** `17dede200000000000000000000000000000000a` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** 45 tests executed, 0 failures, 0 errors, 0 skipped, duration 0.31s
- **Findings:** total=45 · failures=0 · errors=0 · skipped=0- **Artifact:** `examples\self_release\artifacts\junit.xml` (sha256:b8c1a82bcddc8a81ab818e221455266e5c79841518a91be66a06852c25205689)

### `sca-9d7b0348e1cd` — sca_scan

- **Source:** pip-audit (sarif) · version 2.7.3- **Producer:** pip-audit
- **Subject:** `17dede200000000000000000000000000000000a` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** pip-audit reported 1 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=1 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\pip-audit.sarif` (sha256:8aac5fd8a1d3c8ed4d44e5f711a08bbd33086eee6d35b264a24ea802f1a9fee7)

### `sbom-ac2b408199f3` — sbom

- **Source:** cyclonedx (sbom) · version 1.6- **Producer:** cyclonedx
- **Subject:** `secure-sdlc-evidence-collector@0.1.0` (artifact)
- **Status:** generated · **Confidence:** high- **Summary:** CYCLONEDX SBOM with 260 components (spec 1.6)
- **Findings:** components=260- **Artifact:** `examples\self_release\artifacts\sbom.cdx.json` (sha256:5d63731e908da33d976b9c806a00c696e63b68d48fef2a450acc4f3304249564)

### `att-cc948cb8a6a4` — artifact_attestation

- **Source:** manual-attestation (attestation)- **Producer:** build-provenance-manual
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Build provenance recorded: release built from master at commit SHA recorded in release_context, tests and linters passed locally and in CI. SLSA provenance v1 will be produced automatically by GitHub Actions for v0.2.0.
- **Artifact:** `examples\self_release\attestations\artifact_attestation.yaml` (sha256:a5ce3bc13f0a998c46af2e8ad3d2cee22398bb784b36cde782d6883b12c3b453)

### `att-35354bda8818` — artifact_signature

- **Source:** manual-attestation (attestation)- **Producer:** git-tag-signature
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Release integrity anchored by git tag v0.1.0 over commit SHA. A future release (>=0.2.0) will add cosign keyless signing via GitHub Actions OIDC once the public repository and release workflow are in place.
- **Artifact:** `examples\self_release\attestations\artifact_signature.yaml` (sha256:04eafef0f47f279ffcde83ed99e3e1925276dc84057e11f4c2717eca9d71ef39)

### `att-fcee80cf86da` — code_review

- **Source:** manual-attestation (attestation)- **Producer:** solo-maintainer-review
- **Subject:** `PR-0-initial-mvp` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Initial MVP self-reviewed against the project plan and the repository CLAUDE.md quality rules. All quality gates (ruff, mypy --strict, pytest 45/45, 81% coverage) passed before tagging.
- **Artifact:** `examples\self_release\attestations\code_review.yaml` (sha256:774799cc6c75ac31374ff303358331091fc17975bbabd7e03f8324193a133160)

### `att-db21182f1d7e` — dast_scan

- **Source:** manual-attestation (attestation)- **Producer:** appsec-review
- **Subject:** `secure-sdlc-evidence-collector` (application)
- **Status:** passed · **Confidence:** low · manual attestation- **Summary:** Dynamic application security testing is not applicable: the product is a Python CLI and library, it does not expose an HTTP, RPC, or any other networked surface that a DAST scanner could exercise. This attestation documents the non-applicability so SAMM-VERIF-ST-1's recommended DAST evidence is not a silent gap.
- **Artifact:** `examples\self_release\attestations\dast_scan_not_applicable.yaml` (sha256:420c7cdb08d6cb51e4e11a489f38aa3a24b1317a668a4ca7c9bbc9aca4c5f59d)

### `att-eb11de699a36` — pr_metadata

- **Source:** manual-attestation (attestation)- **Producer:** local-git-export
- **Subject:** `PR-0-initial-mvp` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Initial MVP landed on master via fast-forward after local review
- **Artifact:** `examples\self_release\attestations\pr_metadata.yaml` (sha256:2cc684a83115589b472aae473052b06e2948fc3d03c4474ccc075b2b81c3f21a)

### `att-f3bd336bf424` — release_approval

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** v0.1.0 approved for tag and public release after meeting the Definition of Done: bundle, report, summary generated end-to-end, CI pipeline green, README complete, sample fixture reproducible.
- **Artifact:** `examples\self_release\attestations\release_approval.yaml` (sha256:ecc3f85737a75f35d384a922af8de85a81a5fa195cbdeee3a3c2f958f802d4c2)

### `att-6a5b1ef749bc` — rollback_plan

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Rollback plan: revert the v0.1.0 tag and yank the version from PyPI (if published). Downstream consumers can pin the previous commit SHA; no migrations or persistent state are involved in this CLI tool.
- **Artifact:** `examples\self_release\attestations\rollback_plan.yaml` (sha256:f10032275843bfa7baaf328e963b1d2b0122eda518c2a52f8a2b9a4e841a50ac)

### `att-59a2382eb18a` — threat_model

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector` (application)
- **Status:** completed · **Confidence:** medium · manual attestation- **Summary:** Threat model documented in plan doc (sections 15, 19 and 21): assets are the bundle integrity and audit lineage; actors include CI pipelines and downstream auditors; trust boundaries are file ingestion and GitHub API. Mitigations applied: 25MB ingest cap, SHA-256 integrity hashes, strict Pydantic schemas, no secret logging, defusedxml for XML parsing.
- **Artifact:** `examples\self_release\attestations\threat_model.yaml` (sha256:90edc50c0b8fb56f420cd858e4d68a04192a524450f99da010bbc8d02381b606)
