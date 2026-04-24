# Traceability — promise ↔ detection ↔ evidence ↔ result

This document maps every public promise the collector makes (documented in
`README.md`, `CHANGELOG.md`, `SECURITY.md`, and `docs/bundle_schema.md`) to:

1. **Where it is implemented** (module / function).
2. **Which scenario proves it works** (fixture or recorded lab scan).
3. **Expected verdict** for that scenario.
4. **Recorded (obtained) verdict** at the last validation pass.
5. **Negative / edge / misuse counterpart** (where applicable).

Last refreshed: **2026-04-24** (v1.0.0 + readiness pass).

---

## 1 · Ingestion promises

| Promise (README/CHANGELOG) | Implementation | Positive fixture | Negative / edge fixture | Expected | Obtained |
|---|---|---|---|---|---|
| Parse SARIF (Semgrep, CodeQL, Sonar, Snyk Code, Trivy, Grype, Gitleaks, Bandit, pip-audit) | `parsers/sarif.py`, `normalizers/engine.py` | `examples/sample_release/artifacts/semgrep.sarif`, `trivy.sarif`, `gitleaks.sarif` | `tests/unit/test_parsers.py::test_sarif_malformed`, `test_sarif_missing_runs` | parse succeeds on known tools; unknown driver → `evidence_type=sast_scan` (conservative default) | matches |
| Parse CycloneDX SBOM | `parsers/sbom.py` | `examples/sample_release/artifacts/sbom.cdx.json` | `tests/unit/test_parsers.py::test_sbom_invalid_json` | `evidence_type=sbom`, components counted | matches |
| Parse SPDX SBOM | `parsers/sbom.py` | covered via unit test fixture | same | `evidence_type=sbom` | matches |
| Parse JUnit XML | `parsers/junit.py` | `examples/sample_release/artifacts/junit.xml` | `tests/unit/test_parsers.py::test_junit_defused` (XXE guard) | `evidence_type=test_result`, pass/fail counted | matches |
| Parse OWASP ZAP JSON (DAST) | `parsers/zap.py` | `examples/sample_release/artifacts/zap-baseline.json` | `tests/unit/test_zap.py::test_zap_missing_site` | `evidence_type=dast_scan`, alerts bucketed by risk | matches |
| Parse YAML/JSON attestations | `parsers/attestation.py` | `examples/sample_release/attestations/*.yaml` | attestation with unknown key → `extra='forbid'` raises | `evidence_type` derives from `kind` field | matches |
| 25 MB safety cap | `parsers/_common.py::read_bounded` | `tests/unit/test_parsers.py::test_sarif_oversize` | large SARIF → raises `ArtifactTooLargeError` | reject > 25 MB | matches |

## 2 · Classification promises (SARIF → canonical evidence_type)

| Promise | Rule | Source | Expected | Obtained |
|---|---|---|---|---|
| Semgrep → `sast_scan` | driver name contains "semgrep" | `normalizers/engine.py::classify_sarif_driver` | label=`sast_scan` | matches |
| Trivy → `sca_scan` (dominant runs) | driver name contains "trivy" and bulk rules target packages | same | label=`sca_scan`; secret runs reclassified in post | **edge case documented in `docs/limitations.md` §2** |
| Gitleaks → `secrets_scan` | driver name contains "gitleaks" | same | label=`secrets_scan` | matches |
| Bandit → `sast_scan` | driver name contains "bandit" | same | label=`sast_scan` | matches |
| pip-audit → `sca_scan` | driver name contains "pip-audit" | same | label=`sca_scan` | matches |
| Grype → `sca_scan` | driver name contains "grype" | same | label=`sca_scan` | matches |
| Unknown driver | default branch | same | label=`sast_scan` with `confidence=low` tag in rationale | matches |

## 3 · Control evaluation promises

| Control | Framework | Criticality | Required evidence | Recommended evidence | Fixture positive | Fixture negative |
|---|---|---|---|---|---|---|
| SSDF-PW.7 | NIST_SSDF | high | `sast_scan` | — | sample_release | `examples/labs/01-core-saas-lab` (no treatment → partial) |
| SSDF-PW.4 | NIST_SSDF | high | `sca_scan` | — | sample_release | labs (syft+trivy in artifacts) |
| ORG-SECRETS-SCAN | ORG_INTERNAL | high | `secrets_scan` | — | sample_release | labs |
| SSDF-PS.3 | NIST_SSDF | critical | `sbom` | `artifact_attestation`, `artifact_signature` | sample_release | labs (sbom but no signatures → partial) |
| SSDF-PW.8 | NIST_SSDF | high | `test_result` | — | sample_release | labs (no JUnit → missing) |
| ORG-CODE-REVIEW | ORG_INTERNAL | critical | `code_review` | `pr_metadata` | sample_release | labs (missing critical) |
| SSDF-PW.1 | NIST_SSDF | medium | `threat_model` | — | sample_release | labs (missing → `conditional`) |
| ORG-RELEASE-APPROVAL | ORG_INTERNAL | critical | `release_approval` | — | sample_release | labs (missing critical) |
| ORG-REL-ROLLBACK | ORG_INTERNAL | critical | `rollback_plan` | — | sample_release | labs (missing critical) |
| SSDF-PS.2 | NIST_SSDF | critical | `artifact_signature` | `artifact_attestation` | sample_release | labs (missing critical) |
| SAMM-DESIGN-TA-1 | OWASP_SAMM | medium | `threat_model` | — | sample_release | labs (missing → `conditional`) |
| SAMM-IMPL-SB-2 | OWASP_SAMM | high | `sbom` | `artifact_signature`, `artifact_attestation` | sample_release | labs (sbom only) |
| SAMM-VERIF-ST-1 | OWASP_SAMM | high | `sast_scan` | `sca_scan`, `dast_scan` | sample_release | labs (sast+sca no dast) |

## 4 · Release-status rule promises

| Scenario | Expected verdict | Fixture | Obtained |
|---|---|---|---|
| Every critical + high has required evidence | `ready` | `examples/sample_release/` (full) | `ready`, 13/13 |
| Only recommended evidence is missing | `conditional` | `examples/sample_release/` with `artifact_attestation.yaml` removed | `conditional` (reproduced in `tests/integration/test_end_to_end.py::test_conditional_when_only_recommended_missing`) |
| Only medium-criticality controls lack evidence | `conditional` | drop `threat_model.yaml` | `conditional` |
| A critical control lacks required evidence | `not_ready` | sample_release without `--attestations-dir` | `not_ready` (4 missing critical) |
| Vulnerable lab scanned without attestations | `not_ready` | `examples/labs/01-core-saas-lab/` | `not_ready` (6 missing critical) |

## 5 · Determinism & stability promise

| Promise | Test | Expected | Obtained |
|---|---|---|---|
| Two runs on identical inputs produce identical `bundle.json` (after stripping `generated_at`, `evaluated_at`, `bundle_id`) | `tests/integration/test_end_to_end.py::test_bundle_determinism` | diff returns empty | matches |
| `compare` command reports zero deltas for identical bundles | `tests/integration/test_cli.py::test_compare_identical_bundles` | no improvements/regressions | matches |

## 6 · Security promises

| Promise | Implementation | Test |
|---|---|---|
| No token ever logged | `collectors/github.py`, `collectors/gitlab.py` (no `log(token)` calls; headers redacted) | `tests/unit/test_github_collector.py::test_token_not_logged` |
| XML parsed without external entities | `parsers/junit.py` uses `defusedxml` | `tests/unit/test_parsers.py::test_junit_defused` |
| Pydantic `extra='forbid'` on every canonical type | `domain/models.py` `model_config` | `tests/unit/test_domain_models.py::test_bundle_rejects_extra_fields` |
| `--output-dir` does not escape to parent | `application/orchestrator.py` normalizes path | `tests/unit/test_exporters.py::test_output_dir_boundary` |

## 7 · Known gaps still open

See `docs/limitations.md`. Each entry here is a known false-positive or
false-negative risk that the collector does **not** cover and is documented
as part of the public contract.
