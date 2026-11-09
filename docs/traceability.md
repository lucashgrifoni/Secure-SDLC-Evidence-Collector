# Traceability — promise ↔ detection ↔ evidence ↔ result

This document maps the main public promises the collector makes (documented
in `README.md`, `CHANGELOG.md`, `SECURITY.md`, and `docs/bundle_schema.md`)
to:

1. **Where it is implemented** (module / function).
2. **Which scenario proves it works** (fixture or test).
3. **Expected verdict** for that scenario.
4. **Obtained verdict** at the last validation pass.
5. **Negative / edge / misuse counterpart** (where applicable).

How it stays current:

- Every test this page names is checked by
  `tests/unit/test_documented_security_promises.py::test_every_test_named_in_the_traceability_doc_exists`,
  so renaming or deleting one fails the build.
- The §4 release-status rows were re-run against the 4.2.0 code on
  2026-11-09, using the fixtures named in the Fixture column; their
  "Obtained" values come from that run.
- The lab rows in §4 come from the external vulnerable-app corpus, which is
  not public. They were last recorded on 2026-05-17, on a maintainer
  machine, and cannot be reproduced from this repository; see
  [`examples/labs/README.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/labs/README.md).

---

## 1 · Ingestion promises

| Promise (README/CHANGELOG) | Implementation | Positive fixture | Negative / edge fixture | Expected | Obtained |
|---|---|---|---|---|---|
| Parse SARIF (Semgrep, CodeQL, Sonar, Snyk Code, Trivy, Grype, Gitleaks, Bandit, pip-audit) | `parsers/sarif.py`, `normalizers/engine.py` | `examples/sample_release/artifacts/semgrep.sarif`, `trivy.sarif`, `gitleaks.sarif` | `tests/unit/test_parsers.py::test_parse_sarif_semgrep`, `tests/unit/test_parsers.py::test_parse_sarif_requires_runs` | parse succeeds on known tools; unknown driver → `evidence_type=sast_scan` (conservative default) | matches |
| Parse CycloneDX SBOM | `parsers/sbom.py` | `examples/sample_release/artifacts/sbom.cdx.json` | `tests/unit/test_parsers.py::test_parse_sbom_cyclonedx`, `tests/unit/test_parsers.py::test_parse_sbom_spdx` | `evidence_type=sbom`, components counted | matches |
| Parse SPDX SBOM | `parsers/sbom.py` | covered via unit test fixture | same | `evidence_type=sbom` | matches |
| Parse JUnit XML | `parsers/junit.py` | `examples/sample_release/artifacts/junit.xml` | `tests/unit/test_parsers.py::test_parse_junit`, `tests/unit/test_parsers.py::test_parse_junit_rejects_malformed_xml` (XXE guard in `tests/unit/test_documented_security_promises.py`) | `evidence_type=test_result`, pass/fail counted | matches |
| Parse OWASP ZAP JSON (DAST) | `parsers/zap.py` | `examples/sample_release/artifacts/zap-baseline.json` | `tests/unit/test_zap.py::test_parse_zap_rejects_document_without_site`, `tests/unit/test_zap.py::test_parse_zap_counts_severities` | `evidence_type=dast_scan`, alerts bucketed by risk | matches |
| Parse GitLab Security Reports | `parsers/gitlab_security.py` | `tests/fixtures/real/gitlab/*.json` (real analyzer captures) | `tests/unit/test_gitlab_security_report.py` | `scan.type` decides `sast_scan`, `secrets_scan`, `sca_scan` (dependency and container scanning) or `dast_scan`; `scan.status: failure` gives `invalid` | matches |
| Parse YAML/JSON attestations | `parsers/attestation.py` | `examples/sample_release/attestations/*.yaml` | an attestation with an unknown key is refused and reported as a collection error | `evidence_type`, `producer` and `subject_ref` are required; custom data goes under `metadata` | matches |
| 25 MB safety cap | `parsers/_common.py::ensure_file` (`MAX_INPUT_BYTES`) | `tests/unit/test_parser_safety.py::test_oversize_file_hits_safety_cap`, `tests/unit/test_local_collector.py::test_oversized_artifact_is_reported_not_dropped` | large SARIF → raises `ParseError`, reported as a collection error | reject > 25 MB | matches |

## 2 · Classification promises (SARIF → canonical evidence_type)

| Promise | Rule | Source | Expected | Obtained |
|---|---|---|---|---|
| Semgrep → `sast_scan` | driver name contains "semgrep" | `normalizers/engine.py::_classify_sarif_with_provenance` | label=`sast_scan` | matches |
| Trivy SARIF → `sca_scan` | driver name contains "trivy" | same | label=`sca_scan` for every Trivy SARIF run, secret and misconfiguration runs included (no post-classification step); native Trivy JSON is split into separate dependency, secret and IaC records by `normalize_trivy_json` | **edge case documented in `docs/limitations.md` §2** |
| Gitleaks → `secrets_scan` | driver name contains "gitleaks" | same | label=`secrets_scan` | matches |
| Bandit → `sast_scan` | driver name contains "bandit" | same | label=`sast_scan` | matches |
| pip-audit → `sca_scan` | driver name contains "pip-audit" | same | label=`sca_scan` | matches |
| Grype → `sca_scan` | driver name contains "grype" | same | label=`sca_scan` | matches |
| Unknown driver | default branch | same | label=`sast_scan` with `classification.confidence=low`, `classification.reason=fallback_sast` | matches |

## 2b · Promises added after 2.0

| Promise | Implementation | Test |
|---|---|---|
| Native Trivy JSON yields separate dependency, secret and IaC evidence | `parsers/trivy_json.py` | `tests/unit/test_trivy_json.py::test_one_report_yields_three_groups` |
| Package-registry attestations (PyPI PEP 740) record the publisher and predicates | `parsers/registry_attestation.py` | `tests/unit/test_registry_attestation.py::test_pypi_provenance_records_publisher_and_predicates` |
| `vex --consume` applies a statement only to a product of this release | `parsers/vex.py`, `exporters/vex.py` | `tests/unit/test_vex_consumer.py::test_a_statement_about_another_product_does_not_silence_the_release_cve`, `::test_a_statement_naming_a_declared_release_product_applies` |
| `enrich` reads the KEV ransomware flag | `intelligence/` | `tests/unit/test_intelligence.py::test_load_kev_feed_parses_ransomware_flag` |
| `oscal --kind assessment-results` follows OSCAL 1.1.2 | `exporters/oscal.py` | `tests/unit/test_oscal_assessment_results.py::test_assessment_results_shape_matches_oscal_1_1_2` |
| `statement` writes an in-toto Statement v1 whose subject digest is the structural SHA-256 | `exporters/intoto.py` | `tests/unit/test_intoto_export.py::test_build_statement_shape_matches_in_toto_v1`, `::test_subject_digest_matches_structural_sha256` |
| `sarif` writes one result per unmet control | `exporters/sarif_gaps.py` | `tests/unit/test_sarif_gap_export.py::test_each_unmet_control_is_one_result` |
| `guac` emits one document per evidence record | `exporters/guac.py` | `tests/unit/test_profiles_and_guac.py::test_guac_adapter_emits_one_document_per_evidence` |

Regulatory profiles (CRA, FedRAMP CR26) are covered in
[evidence profile migration](evidence-profile-migration.md).

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
| Every control is met, waived or not applicable, with no required or recommended evidence missing | `ready` | `examples/sample_release/` (full) | `ready`, 13/13 met, exit `0` |
| A high control lacks required evidence | `conditional` | `examples/sample_release/` with `artifacts/semgrep.sarif` removed | `conditional`, `SSDF-PW.7` and `SAMM-VERIF-ST-1` missing, exit `0` under the default `--fail-on not_ready` |
| Only recommended evidence is missing | `conditional` | `examples/sample_release/` with `artifact_attestation.yaml` removed | `conditional`, 10 met and 3 partial, exit `0` (also `tests/unit/test_scoring.py::test_release_conditional_when_only_medium_gap`) |
| Only medium-criticality controls lack evidence | `conditional` | drop `threat_model.yaml` | `conditional`, `SSDF-PW.1` and `SAMM-DESIGN-TA-1` missing, exit `0` |
| A critical control lacks required evidence | `not_ready` | sample_release without `--attestations-dir` | `not_ready`, exit `2` (4 missing critical: `ORG-CODE-REVIEW`, `ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`) |
| Vulnerable lab scanned without attestations | `not_ready` | `examples/labs/01-core-saas-lab/` | `not_ready` (4 missing critical: `ORG-CODE-REVIEW`, `ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`), maintainer-local, recorded 2026-05-17 |
| Vulnerable lab with weaker SBOM coverage | `not_ready` | `examples/labs/04-data-batch-lab/` | `not_ready` (5 missing critical: the same four plus `SSDF-PS.3` because no SBOM attestation is present), maintainer-local, recorded 2026-05-17 |
| Vulnerable lab where `sca_scan` is present | `not_ready` | `examples/labs/06-industry-regulated-lab/` | `not_ready` (4 missing critical; one extra control met because `pip-audit` evidence raises `SSDF-PW.4` to `met`), maintainer-local, recorded 2026-05-17 |

## 5 · Determinism & stability promise

| Promise | Test | Expected | Obtained |
|---|---|---|---|
| Two runs on identical inputs produce identical `bundle.json` (after stripping `generated_at`, `evaluated_at`, `bundle_id`) | `tests/integration/test_determinism.py::test_sample_release_bundle_is_deterministic` | diff returns empty | matches |
| Artifact discovery order does not change the bundle | `tests/integration/test_determinism.py::test_sample_release_bundle_is_stable_across_artifact_reorder` | identical structural hash | matches |
| The structural hash holds under every profile | `tests/integration/test_determinism.py::test_structural_hash_is_stable_under_every_profile` | identical structural hash | matches |
| `compare` command reports zero deltas for identical bundles | `tests/integration/test_cli_more_commands.py::test_compare_emits_zero_delta_for_identical_bundles` | no improvements/regressions | matches |
| The sample release keeps its pinned structural digest (`e859f475…` since 4.0.0) | `tests/integration/test_bundle_snapshot.py::test_sample_release_bundle_sha256_snapshot` | digest equals `tests/fixtures/sample_release_snapshot.sha256` | matches |

## 6 · Security promises

| Promise | Implementation | Test |
|---|---|---|
| No token ever logged | `collectors/github.py`, `collectors/gitlab.py` (no `log(token)` calls; the token is also kept out of the config `repr`) | `tests/unit/test_documented_security_promises.py::test_a_github_token_never_reaches_a_log_record`, `::test_a_gitlab_token_never_reaches_a_log_record`, `::test_a_collector_config_does_not_render_its_token` |
| XML parsed without external entities, and entity expansion refused | `parsers/junit.py` uses `defusedxml` | `tests/unit/test_documented_security_promises.py::test_an_external_entity_is_never_expanded_when_parsing_junit_xml`, `::test_entity_expansion_is_refused_rather_than_expanded` |
| Pydantic `extra='forbid'` on every canonical type | `domain/models.py` `model_config` on the shared `_BaseModel` | `tests/unit/test_documented_security_promises.py::test_every_canonical_model_is_configured_to_forbid_unknown_fields`, `::test_no_canonical_model_actually_accepts_an_unknown_field` |
| A hostile artifact cannot take the collection down with it | `collectors/local.py` shared ingestion guard | `tests/unit/test_hostile_input_containment.py` |

Every test named above was verified to exist and pass on 2026-08-25. The row
that used to sit at the end of this table claimed `--output-dir` could not
escape to a parent, implemented by a path normalization in
`application/orchestrator.py`. Neither part was true: the orchestrator calls
`output_dir.mkdir(parents=True, exist_ok=True)` and nothing else, and
`--output-dir a/b/../../c` writes to `c`. That is ordinary behaviour for a CLI
output flag — it honours the path the operator typed, the way `cp` does — so
the row was removed rather than the behaviour changed. If you are wiring
`--output-dir` from an untrusted value in a workflow, constrain it there; this
tool does not.

## 7 · Known gaps still open

See `docs/limitations.md`. Each entry here is a known false-positive or
false-negative risk that the collector does **not** cover and is documented
as part of the public contract.
