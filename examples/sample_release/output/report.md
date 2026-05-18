# Secure SDLC Evidence Report

**Bundle ID:** `bundle-20260518-payments-api-2026.04.10-fb2d5a16`
**Bundle version:** 1.0.0
**Generated at:** 2026-05-18T12:20:30.416661+00:00

## Application

| Field | Value |
|-------|-------|
| Name | `payments-api` |
| Repository | `acme/payments-api` |
| Environment | production |
| Owner team | - |

## Release

| Field | Value |
|-------|-------|
| Release ID | `2026.04.10` |
| Commit SHA | `abcdef1234567890` |
| Branch | `main` |
| Pipeline run | - |
| Build ID | - |
| Artifact digest | `-` |
| Tag | - |

## Verdict

- **Release status:** `ready`
- **Evidence coverage score:** 100/100
- **Confidence score:** 59/100
- **Controls:** 13 met · 0 partial · 0 missing · 0 waived · 0 n/a
- **Missing critical evidence:** none

## Control evaluations

| Control | Framework | Status | Criticality | Confidence | Evidence refs |
|---------|-----------|--------|-------------|------------|---------------|
| `SSDF-PW.7` | NIST_SSDF | **met** | high | high | sast-cfcf7a634b32 |
| `SSDF-PW.4` | NIST_SSDF | **met** | high | high | sca-54e49b31bec7 |
| `ORG-SECRETS-SCAN` | ORG_INTERNAL | **met** | high | high | secrets-3bc6ef3a7a0a |
| `SSDF-PS.3` | NIST_SSDF | **met** | critical | low | sbom-8f24db8264b4, att-eeab3847be8e, att-4fdd0c6e65a1 |
| `SSDF-PW.8` | NIST_SSDF | **met** | high | high | test-3ba115181f49 |
| `ORG-CODE-REVIEW` | ORG_INTERNAL | **met** | critical | low | att-61dda6456f8e, att-b0fcf22e94ec |
| `SSDF-PW.1` | NIST_SSDF | **met** | medium | low | att-361af230e38f |
| `ORG-RELEASE-APPROVAL` | ORG_INTERNAL | **met** | critical | low | att-2cfa2bc287a7 |
| `ORG-REL-ROLLBACK` | ORG_INTERNAL | **met** | critical | low | att-790592cda958 |
| `SSDF-PS.2` | NIST_SSDF | **met** | critical | low | att-4fdd0c6e65a1, att-eeab3847be8e |
| `SAMM-DESIGN-TA-1` | OWASP_SAMM | **met** | medium | low | att-361af230e38f |
| `SAMM-IMPL-SB-2` | OWASP_SAMM | **met** | high | low | sbom-8f24db8264b4, att-4fdd0c6e65a1, att-eeab3847be8e |
| `SAMM-VERIF-ST-1` | OWASP_SAMM | **met** | high | high | sast-cfcf7a634b32, sca-54e49b31bec7, dast-f6a61122d5a3 |

### Rationales

- **`SSDF-PW.7` — Review and/or analyze human-readable code (SAST)**
  Control SSDF-PW.7 is met by evidence ['sast-cfcf7a634b32'].
- **`SSDF-PW.4` — Reuse existing, well-secured software (SCA)**
  Control SSDF-PW.4 is met by evidence ['sca-54e49b31bec7'].
- **`ORG-SECRETS-SCAN` — Repository-wide secrets scanning**
  Control ORG-SECRETS-SCAN is met by evidence ['secrets-3bc6ef3a7a0a'].
- **`SSDF-PS.3` — Archive and protect each software release (SBOM)**
  Control SSDF-PS.3 is met by evidence ['sbom-8f24db8264b4', 'att-eeab3847be8e', 'att-4fdd0c6e65a1'].
- **`SSDF-PW.8` — Test executable code to identify vulnerabilities**
  Control SSDF-PW.8 is met by evidence ['test-3ba115181f49'].
- **`ORG-CODE-REVIEW` — Code review by eligible reviewers**
  Control ORG-CODE-REVIEW is met by evidence ['att-61dda6456f8e', 'att-b0fcf22e94ec'].
- **`SSDF-PW.1` — Design software to meet security requirements (threat model)**
  Control SSDF-PW.1 is met by evidence ['att-361af230e38f'].
- **`ORG-RELEASE-APPROVAL` — Formal release approval**
  Control ORG-RELEASE-APPROVAL is met by evidence ['att-2cfa2bc287a7'].
- **`ORG-REL-ROLLBACK` — Rollback plan exists and was approved**
  Control ORG-REL-ROLLBACK is met by evidence ['att-790592cda958'].
- **`SSDF-PS.2` — Provide a mechanism to verify software release integrity**
  Control SSDF-PS.2 is met by evidence ['att-4fdd0c6e65a1', 'att-eeab3847be8e'].
- **`SAMM-DESIGN-TA-1` — Threat Assessment (Design / Threat Assessment 1)**
  Control SAMM-DESIGN-TA-1 is met by evidence ['att-361af230e38f'].
- **`SAMM-IMPL-SB-2` — Secure Build (Implementation / Secure Build 2)**
  Control SAMM-IMPL-SB-2 is met by evidence ['sbom-8f24db8264b4', 'att-4fdd0c6e65a1', 'att-eeab3847be8e'].
- **`SAMM-VERIF-ST-1` — Security Testing (Verification / Security Testing 1)**
  Control SAMM-VERIF-ST-1 is met by evidence ['sast-cfcf7a634b32', 'sca-54e49b31bec7', 'dast-f6a61122d5a3'].


## Gaps

No gaps detected.

## Evidence inventory

| ID | Type | Status | Confidence | Producer | Subject |
|----|------|--------|------------|----------|---------|
| `secrets-3bc6ef3a7a0a` | secrets_scan | passed | high | gitleaks | `abcdef1234567890` |
| `test-3ba115181f49` | test_result | passed | high | payments-api-suite | `abcdef1234567890` |
| `sbom-8f24db8264b4` | sbom | generated | high | cyclonedx | `pkg:generic/acme/payments-api@2026.04.10` |
| `sast-cfcf7a634b32` | sast_scan | passed | high | semgrep | `abcdef1234567890` |
| `sca-54e49b31bec7` | sca_scan | passed | high | trivy | `abcdef1234567890` |
| `dast-f6a61122d5a3` | dast_scan | passed | high | OWASP ZAP | `http./sample_release` |
| `att-eeab3847be8e` | artifact_attestation | passed | medium | cosign-attestation | `payments-api:2026.04.10` |
| `att-4fdd0c6e65a1` | artifact_signature | passed | medium | cosign | `payments-api:2026.04.10` |
| `att-61dda6456f8e` | code_review | passed | medium | github-pull-request | `PR-184` |
| `att-b0fcf22e94ec` | pr_metadata | passed | medium | github-pull-request-export | `PR-184` |
| `att-2cfa2bc287a7` | release_approval | passed | medium | Change Advisory Board | `payments-api:2026.04.10` |
| `att-790592cda958` | rollback_plan | passed | medium | Release Manager | `payments-api:2026.04.10` |
| `att-361af230e38f` | threat_model | completed | medium | AppSec Team | `payments-api` |

### `secrets-3bc6ef3a7a0a` — secrets_scan

- **Source:** gitleaks (sarif) · version 8.18.4- **Producer:** gitleaks
- **Subject:** `abcdef1234567890` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** gitleaks reported 0 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=0 · low=0 · info=0- **Artifact:** `examples\sample_release\artifacts\gitleaks.sarif` (sha256:3ccb3d37a2b3a6ee3a3146a6bedd8238addb4e138f0492555803a4c4b7fd534b)

### `test-3ba115181f49` — test_result

- **Source:** junit (junit-xml)- **Producer:** payments-api-suite
- **Subject:** `abcdef1234567890` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** 42 tests executed, 0 failures, 0 errors, 1 skipped, duration 8.42s
- **Findings:** total=42 · failures=0 · errors=0 · skipped=1- **Artifact:** `examples\sample_release\artifacts\junit.xml` (sha256:fa65f270998190cd0014fe7f09b3e4c7e69b898913702d3bd48b3eab2cf87e43)

### `sbom-8f24db8264b4` — sbom

- **Source:** cyclonedx (sbom) · version 1.5- **Producer:** cyclonedx
- **Subject:** `pkg:generic/acme/payments-api@2026.04.10` (artifact)
- **Status:** generated · **Confidence:** high- **Summary:** CYCLONEDX SBOM with 3 components (spec 1.5)
- **Findings:** components=3- **Artifact:** `examples\sample_release\artifacts\sbom.cdx.json` (sha256:84088064a42486df71ca5567ce4857b6b6ecf1a5445f76166c19c83057ed977e)

### `sast-cfcf7a634b32` — sast_scan

- **Source:** semgrep (sarif) · version 1.70.0- **Producer:** semgrep
- **Subject:** `abcdef1234567890` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** semgrep reported 2 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=1 · low=1 · info=0- **Artifact:** `examples\sample_release\artifacts\semgrep.sarif` (sha256:7b0a9f4e140945d4bec39ffb4f2340366336e1d74c639bccf2d33dcf74f969ef)

### `sca-54e49b31bec7` — sca_scan

- **Source:** trivy (sarif) · version 0.52.0- **Producer:** trivy
- **Subject:** `abcdef1234567890` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** trivy reported 1 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=1 · low=0 · info=0- **Artifact:** `examples\sample_release\artifacts\trivy.sarif` (sha256:acab632c4fa3302c2c6acba37a5c4f36630b7993df1fd14bb94ebe165da25c5d)

### `dast-f6a61122d5a3` — dast_scan

- **Source:** OWASP ZAP (dast) · version 2.14.0- **Producer:** OWASP ZAP
- **Subject:** `http./sample_release` (application)
- **Status:** passed · **Confidence:** high- **Summary:** OWASP ZAP DAST reported 3 findings across 1 target(s); high/critical=0
- **Findings:** critical=0 · high=0 · medium=0 · low=1 · info=2- **Artifact:** `examples\sample_release\artifacts\zap-baseline.json` (sha256:c5bb8ca639728d37dd4fee2a629e39de4e0510b307e560d1b1f77d4c5d9067db)

### `att-eeab3847be8e` — artifact_attestation

- **Source:** manual-attestation (attestation)- **Producer:** cosign-attestation
- **Subject:** `payments-api:2026.04.10` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** SLSA build provenance attestation generated for the release artifact
- **Artifact:** `examples\sample_release\attestations\artifact_attestation.yaml` (sha256:2d98bd13086735eb367c62290df3989ec04443030bf590f7762e122ec9c140cd)

### `att-4fdd0c6e65a1` — artifact_signature

- **Source:** manual-attestation (attestation)- **Producer:** cosign
- **Subject:** `payments-api:2026.04.10` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Artifact signed with cosign using keyless OIDC flow
- **Artifact:** `examples\sample_release\attestations\artifact_signature.yaml` (sha256:3fe2f1b0ebf3ba4b1f03e5778b04d99b7d555fc4dd3de66e04dbb5e7d794c2ab)

### `att-61dda6456f8e` — code_review

- **Source:** manual-attestation (attestation)- **Producer:** github-pull-request
- **Subject:** `PR-184` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** PR-184 approved by 2 reviewers after last commit
- **Artifact:** `examples\sample_release\attestations\code_review.yaml` (sha256:5df9fdb7e6774c36d1c40c0292fca75bb1af831161e6b9b6344c46067174ec40)

### `att-b0fcf22e94ec` — pr_metadata

- **Source:** manual-attestation (attestation)- **Producer:** github-pull-request-export
- **Subject:** `PR-184` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Exported PR-184 metadata: 2 approvals after last commit, CI green
- **Artifact:** `examples\sample_release\attestations\pr_metadata.yaml` (sha256:d610fdcc08aff91fe6ba8029a6b83fc50838dcb54e3b8a75a1486c15ac833840)

### `att-2cfa2bc287a7` — release_approval

- **Source:** manual-attestation (attestation)- **Producer:** Change Advisory Board
- **Subject:** `payments-api:2026.04.10` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Release 2026.04.10 formally approved by CAB
- **Artifact:** `examples\sample_release\attestations\release_approval.yaml` (sha256:35641e1d797d269ed57a32ff62b20524b0f3f54e81af8d7fbbdcf2201fb05a95)

### `att-790592cda958` — rollback_plan

- **Source:** manual-attestation (attestation)- **Producer:** Release Manager
- **Subject:** `payments-api:2026.04.10` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Documented rollback plan in runbook with 15 min MTTR target
- **Artifact:** `examples\sample_release\attestations\rollback_plan.yaml` (sha256:9b7aced1f6f379dcec6fabe176ccef7f64f5dc7de1d02c566c3e0aa9ea321099)

### `att-361af230e38f` — threat_model

- **Source:** manual-attestation (attestation)- **Producer:** AppSec Team
- **Subject:** `payments-api` (application)
- **Status:** completed · **Confidence:** medium · manual attestation- **Summary:** Threat model updated for payments-api refund flow
- **Artifact:** `examples\sample_release\attestations\threat_model.yaml` (sha256:f6d5ec38328ef7dd319e39f78e2fc53cc78dede302c0d85dfb25fb1b870acce6)
