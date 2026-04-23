# Secure SDLC Evidence Report

**Bundle ID:** `bundle-20260423-secure-sdlc-evidence-collector-v0.1.0-52f9a666`
**Bundle version:** 1.0.0
**Generated at:** 2026-04-23T20:46:05.571370+00:00

## Application

| Field | Value |
|-------|-------|
| Name | `secure-sdlc-evidence-collector` |
| Repository | `LucasGrifoni/secure-sdlc-evidence-collector` |
| Environment | production |
| Owner team | - |

## Release

| Field | Value |
|-------|-------|
| Release ID | `v0.1.0` |
| Commit SHA | `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` |
| Branch | `main` |
| Pipeline run | - |
| Build ID | - |
| Artifact digest | `-` |
| Tag | - |

## Verdict

- **Release status:** `ready`
- **Evidence coverage score:** 100/100
- **Confidence score:** 60/100
- **Controls:** 10 met · 0 partial · 0 missing · 0 waived · 0 n/a
- **Missing critical evidence:** none

## Control evaluations

| Control | Framework | Status | Criticality | Confidence | Evidence refs |
|---------|-----------|--------|-------------|------------|---------------|
| `SSDF-PW.7` | NIST_SSDF | **met** | high | high | sast-82e76dd35927 |
| `SSDF-PW.4` | NIST_SSDF | **met** | high | high | sca-cde6f78b98f8 |
| `ORG-SECRETS-SCAN` | ORG_INTERNAL | **met** | high | high | secrets-ef72699eff3d |
| `SSDF-PS.3` | NIST_SSDF | **met** | critical | low | sbom-37f7855f8da4, att-493e5e23d0db, att-5602f00380e5 |
| `SSDF-PW.8` | NIST_SSDF | **met** | high | high | test-947163ade642 |
| `ORG-CODE-REVIEW` | ORG_INTERNAL | **met** | critical | low | att-344346777d59, att-352e828da303 |
| `SSDF-PW.1` | NIST_SSDF | **met** | medium | low | att-1eebf84557e5 |
| `ORG-RELEASE-APPROVAL` | ORG_INTERNAL | **met** | critical | low | att-29b0bfd8ba67 |
| `ORG-REL-ROLLBACK` | ORG_INTERNAL | **met** | critical | low | att-713ed6db892c |
| `SSDF-PS.2` | NIST_SSDF | **met** | critical | low | att-5602f00380e5, att-493e5e23d0db |

### Rationales

- **`SSDF-PW.7` — Review and/or analyze human-readable code (SAST)**
  Control SSDF-PW.7 is met by evidence ['sast-82e76dd35927'].
- **`SSDF-PW.4` — Reuse existing, well-secured software (SCA)**
  Control SSDF-PW.4 is met by evidence ['sca-cde6f78b98f8'].
- **`ORG-SECRETS-SCAN` — Repository-wide secrets scanning**
  Control ORG-SECRETS-SCAN is met by evidence ['secrets-ef72699eff3d'].
- **`SSDF-PS.3` — Archive and protect each software release (SBOM)**
  Control SSDF-PS.3 is met by evidence ['sbom-37f7855f8da4', 'att-493e5e23d0db', 'att-5602f00380e5'].
- **`SSDF-PW.8` — Test executable code to identify vulnerabilities**
  Control SSDF-PW.8 is met by evidence ['test-947163ade642'].
- **`ORG-CODE-REVIEW` — Code review by eligible reviewers**
  Control ORG-CODE-REVIEW is met by evidence ['att-344346777d59', 'att-352e828da303'].
- **`SSDF-PW.1` — Design software to meet security requirements (threat model)**
  Control SSDF-PW.1 is met by evidence ['att-1eebf84557e5'].
- **`ORG-RELEASE-APPROVAL` — Formal release approval**
  Control ORG-RELEASE-APPROVAL is met by evidence ['att-29b0bfd8ba67'].
- **`ORG-REL-ROLLBACK` — Rollback plan exists and was approved**
  Control ORG-REL-ROLLBACK is met by evidence ['att-713ed6db892c'].
- **`SSDF-PS.2` — Provide a mechanism to verify software release integrity**
  Control SSDF-PS.2 is met by evidence ['att-5602f00380e5', 'att-493e5e23d0db'].


## Gaps

No gaps detected.

## Evidence inventory

| ID | Type | Status | Confidence | Producer | Subject |
|----|------|--------|------------|----------|---------|
| `sast-82e76dd35927` | sast_scan | passed | high | Bandit | `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` |
| `secrets-ef72699eff3d` | secrets_scan | passed | high | gitleaks | `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` |
| `test-947163ade642` | test_result | passed | high | pytest tests | `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` |
| `sca-cde6f78b98f8` | sca_scan | passed | high | pip-audit | `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` |
| `sbom-37f7855f8da4` | sbom | generated | high | cyclonedx | `secure-sdlc-evidence-collector@0.1.0` |
| `att-493e5e23d0db` | artifact_attestation | passed | medium | build-provenance-manual | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-5602f00380e5` | artifact_signature | passed | medium | git-tag-signature | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-344346777d59` | code_review | passed | medium | solo-maintainer-review | `PR-0-initial-mvp` |
| `att-352e828da303` | pr_metadata | passed | medium | local-git-export | `PR-0-initial-mvp` |
| `att-29b0bfd8ba67` | release_approval | passed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-713ed6db892c` | rollback_plan | passed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector:v0.1.0` |
| `att-1eebf84557e5` | threat_model | completed | medium | Lucas Henrique Grifoni | `secure-sdlc-evidence-collector` |

### `sast-82e76dd35927` — sast_scan

- **Source:** Bandit (sarif) · version 1.9.4- **Producer:** Bandit
- **Subject:** `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** Bandit reported 0 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=0 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\bandit.sarif` (sha256:6151c50a450775e48b1847446678e214b8ce72f32fac4f14b8750cbbbfda5079)

### `secrets-ef72699eff3d` — secrets_scan

- **Source:** gitleaks (sarif) · version v8.0.0- **Producer:** gitleaks
- **Subject:** `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** gitleaks reported 0 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=0 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\gitleaks.sarif` (sha256:584cd83dfa44420f9476f34127486161374ffc53bbb24700444e43d8e202cd68)

### `test-947163ade642` — test_result

- **Source:** junit (junit-xml)- **Producer:** pytest tests
- **Subject:** `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** 45 tests executed, 0 failures, 0 errors, 0 skipped, duration 0.31s
- **Findings:** total=45 · failures=0 · errors=0 · skipped=0- **Artifact:** `examples\self_release\artifacts\junit.xml` (sha256:b8c1a82bcddc8a81ab818e221455266e5c79841518a91be66a06852c25205689)

### `sca-cde6f78b98f8` — sca_scan

- **Source:** pip-audit (sarif) · version 2.7.3- **Producer:** pip-audit
- **Subject:** `2107bdc73e03ce0a2349b5ba8cfe8e00b9218083` (commit)
- **Status:** passed · **Confidence:** high- **Summary:** pip-audit reported 1 findings (high/critical=0)
- **Findings:** critical=0 · high=0 · medium=1 · low=0 · info=0- **Artifact:** `examples\self_release\artifacts\pip-audit.sarif` (sha256:7ee172f0c776bcd4da2270283685d347874a22423a3884ff43455d9ba8d0c83f)

### `sbom-37f7855f8da4` — sbom

- **Source:** cyclonedx (sbom) · version 1.6- **Producer:** cyclonedx
- **Subject:** `secure-sdlc-evidence-collector@0.1.0` (artifact)
- **Status:** generated · **Confidence:** high- **Summary:** CYCLONEDX SBOM with 260 components (spec 1.6)
- **Findings:** components=260- **Artifact:** `examples\self_release\artifacts\sbom.cdx.json` (sha256:32aa9473c1e08d95e7db6755a866cf2bb7e0ee42ca1587d259e802280679fa0a)

### `att-493e5e23d0db` — artifact_attestation

- **Source:** manual-attestation (attestation)- **Producer:** build-provenance-manual
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Build provenance recorded: release built from master at commit SHA recorded in release_context, tests and linters passed locally and in CI. SLSA provenance v1 will be produced automatically by GitHub Actions for v0.2.0.
- **Artifact:** `examples\self_release\attestations\artifact_attestation.yaml` (sha256:a5ce3bc13f0a998c46af2e8ad3d2cee22398bb784b36cde782d6883b12c3b453)

### `att-5602f00380e5` — artifact_signature

- **Source:** manual-attestation (attestation)- **Producer:** git-tag-signature
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (artifact)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Release integrity anchored by git tag v0.1.0 over commit SHA. A future release (>=0.2.0) will add cosign keyless signing via GitHub Actions OIDC once the public repository and release workflow are in place.
- **Artifact:** `examples\self_release\attestations\artifact_signature.yaml` (sha256:04eafef0f47f279ffcde83ed99e3e1925276dc84057e11f4c2717eca9d71ef39)

### `att-344346777d59` — code_review

- **Source:** manual-attestation (attestation)- **Producer:** solo-maintainer-review
- **Subject:** `PR-0-initial-mvp` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Initial MVP self-reviewed against the project plan and the repository CLAUDE.md quality rules. All quality gates (ruff, mypy --strict, pytest 45/45, 81% coverage) passed before tagging.
- **Artifact:** `examples\self_release\attestations\code_review.yaml` (sha256:774799cc6c75ac31374ff303358331091fc17975bbabd7e03f8324193a133160)

### `att-352e828da303` — pr_metadata

- **Source:** manual-attestation (attestation)- **Producer:** local-git-export
- **Subject:** `PR-0-initial-mvp` (pull_request)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Initial MVP landed on master via fast-forward after local review
- **Artifact:** `examples\self_release\attestations\pr_metadata.yaml` (sha256:2cc684a83115589b472aae473052b06e2948fc3d03c4474ccc075b2b81c3f21a)

### `att-29b0bfd8ba67` — release_approval

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** v0.1.0 approved for tag and public release after meeting the Definition of Done: bundle, report, summary generated end-to-end, CI pipeline green, README complete, sample fixture reproducible.
- **Artifact:** `examples\self_release\attestations\release_approval.yaml` (sha256:ecc3f85737a75f35d384a922af8de85a81a5fa195cbdeee3a3c2f958f802d4c2)

### `att-713ed6db892c` — rollback_plan

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector:v0.1.0` (release)
- **Status:** passed · **Confidence:** medium · manual attestation- **Summary:** Rollback plan: revert the v0.1.0 tag and yank the version from PyPI (if published). Downstream consumers can pin the previous commit SHA; no migrations or persistent state are involved in this CLI tool.
- **Artifact:** `examples\self_release\attestations\rollback_plan.yaml` (sha256:f10032275843bfa7baaf328e963b1d2b0122eda518c2a52f8a2b9a4e841a50ac)

### `att-1eebf84557e5` — threat_model

- **Source:** manual-attestation (attestation)- **Producer:** Lucas Henrique Grifoni
- **Subject:** `secure-sdlc-evidence-collector` (application)
- **Status:** completed · **Confidence:** medium · manual attestation- **Summary:** Threat model documented in plan doc (sections 15, 19 and 21): assets are the bundle integrity and audit lineage; actors include CI pipelines and downstream auditors; trust boundaries are file ingestion and GitHub API. Mitigations applied: 25MB ingest cap, SHA-256 integrity hashes, strict Pydantic schemas, no secret logging, defusedxml for XML parsing.
- **Artifact:** `examples\self_release\attestations\threat_model.yaml` (sha256:90edc50c0b8fb56f420cd858e4d68a04192a524450f99da010bbc8d02381b606)

