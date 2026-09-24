# Traceability — promise ↔ detection ↔ evidence ↔ result

This document maps every public promise the collector makes (documented in
`README.md`, `CHANGELOG.md`, `SECURITY.md`, and `docs/bundle_schema.md`) to:

1. **Where it is implemented** (module / function).
2. **Which scenario proves it works** (fixture or recorded lab scan).
3. **Expected verdict** for that scenario.
4. **Recorded (obtained) verdict** at the last validation pass.
5. **Negative / edge / misuse counterpart** (where applicable).

Last refreshed: **2026-05-05** (maturity/higiene rodada on top of the
`v1.1.0` release-readiness merge in `main`, commit `17dede2`).

### Refresh notes — 2026-05-17

What was re-run in this rodada (post-publication hardening branch
`chore/post-publication-hardening-v1-1-1`, evidence captured under
[`output/publication-2026-05-17/`](../output/publication-2026-05-17/)):

- **All 7 lab scenarios** (`examples/labs/01..07`) — every lab produced
  the expected `release_status = not_ready` with `--fail-on not_ready`
  exit `2`. Critical-missing counts: 4 for labs 01, 02, 03, 05, 06, 07
  and 5 for lab 04 (which lacks an SBOM attestation). The §4 row for
  `01-core-saas-lab` was updated from the previous "(6 missing
  critical)" — a stale number inherited from before the catalog
  consolidated `SAMM-IMPL-SB-2` and `SAMM-VERIF-ST-1` into `partial`.
- **Sample-release positive** — `ready 13/13`, coverage 100, confidence
  59 (matches §3, §4).
- **Sample-release negative** (`--fail-on not_ready`) — `not_ready`,
  4 missing critical (`ORG-CODE-REVIEW`, `ORG-RELEASE-APPROVAL`,
  `ORG-REL-ROLLBACK`, `SSDF-PS.2`), exit `2`.
- **Self-release dogfood** (`make run-self-release`) — `ready 13/13`,
  coverage 100, confidence 54 (manual attestations). The generated
  bundle under `output/self_release/` was regenerated locally to match
  the v1.1.0 schema (now includes the `classification` field introduced
  in fase 7).
- **Cross-OS determinism** — the snapshot test now produces digest
  `a42920b3…` on both Windows and Linux after the 2026-05-17 fix to
  `normalize_bundle` (POSIX-normalizes `evidence[*].raw.artifact_path`
  at hash time). See `CHANGELOG.md` *Fixed — 2026-05-17* and
  `tests/unit/test_integrity.py`.

What was **not** re-run:

- Docker build (daemon not active on the validation host).
- `trivy` and `cross-os` CI matrix (require external tooling /
  multi-runner CI). Both still run as required checks in
  `security-ci-cd.yml` and `github-ci-cd.yml`.

### Refresh notes — 2026-05-05

What was re-run from this matrix in this rodada:

- **Sample-release positive fixture (`examples/sample_release/`)** —
  `python -m evidence_collector.cli.main run` produced
  `release_status = ready`, coverage 100, confidence 59, **13/13
  controls met**, evidence count 13. The four output directories
  used were `output/cursor-validation-{run,collect,evaluate,oscal,schema}`
  and were cleaned at the end of the rodada.
- **Sample-release negative scenario (no `--attestations-dir`)** —
  produced `release_status = not_ready`, coverage 47, confidence 100,
  **6 missing**, **2 partial**, **5 met**, exit code `2` by design.
  Missing critical controls observed: `ORG-CODE-REVIEW`,
  `ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`. This
  matches §4 row "A critical control lacks required evidence".
- **`compare` against the generated sample** —
  `output/sample_release/bundle.json` vs. the new
  `output/cursor-validation-run/bundle.json` reported
  `coverage_delta=0`, `confidence_delta=0`, all 13 controls
  `unchanged`. The `ready -> ready` headline is preserved across the
  rename (the canonical sample still ships under the
  `payments-api / 2026.04.10` release context, so the bundle IDs
  differ — that is by design, not a regression).
- **`oscal` and `schema` exports** — both succeeded with
  deterministic UUID/JSON output as documented in §5.

What was **not** re-run in this rodada:

- `examples/labs/*` — the recorded lab scans were not re-driven.
  None of the lab fixtures changed since 2026-04-24, so the §3 lab
  rows are reported as "matches" by inheritance from the previous
  pass. To revalidate, run `bash scripts/scan_all_labs.sh` from a
  shell with the original lab corpus mounted (Bash on Windows is
  available via Git Bash; the helper script does not need to be
  rewritten for PowerShell).
- The GitHub / GitLab collectors against live APIs — no token was
  set in this rodada (`doctor --json` reports both as
  `absent (collectors will skip SCM)`). The unit and contract tests
  for both collectors are exercised by the regular `pytest` run
  documented in `release-readiness.md`.
- Docker build — Docker daemon not active in this pass. The §4
  fixture rows that depend on the container fall back to the local
  CLI invocation.

Refresh outcome: every row in §1, §2, §3 and §4 is consistent with
what the CLI produced on 2026-05-05. No row needed an `obtained ≠
expected` correction.

---

## 1 · Ingestion promises

| Promise (README/CHANGELOG) | Implementation | Positive fixture | Negative / edge fixture | Expected | Obtained |
|---|---|---|---|---|---|
| Parse SARIF (Semgrep, CodeQL, Sonar, Snyk Code, Trivy, Grype, Gitleaks, Bandit, pip-audit) | `parsers/sarif.py`, `normalizers/engine.py` | `examples/sample_release/artifacts/semgrep.sarif`, `trivy.sarif`, `gitleaks.sarif` | `tests/unit/test_parsers.py::test_parse_sarif_semgrep`, `tests/unit/test_parsers.py::test_parse_sarif_requires_runs` | parse succeeds on known tools; unknown driver → `evidence_type=sast_scan` (conservative default) | matches |
| Parse CycloneDX SBOM | `parsers/sbom.py` | `examples/sample_release/artifacts/sbom.cdx.json` | `tests/unit/test_parsers.py::test_parse_sbom_cyclonedx`, `tests/unit/test_parsers.py::test_parse_sbom_spdx` | `evidence_type=sbom`, components counted | matches |
| Parse SPDX SBOM | `parsers/sbom.py` | covered via unit test fixture | same | `evidence_type=sbom` | matches |
| Parse JUnit XML | `parsers/junit.py` | `examples/sample_release/artifacts/junit.xml` | `tests/unit/test_parsers.py::test_parse_junit`, `tests/unit/test_parsers.py::test_parse_junit_rejects_malformed_xml` (XXE guard in `tests/unit/test_documented_security_promises.py`) | `evidence_type=test_result`, pass/fail counted | matches |
| Parse OWASP ZAP JSON (DAST) | `parsers/zap.py` | `examples/sample_release/artifacts/zap-baseline.json` | `tests/unit/test_zap.py::test_parse_zap_rejects_document_without_site`, `tests/unit/test_zap.py::test_parse_zap_counts_severities` | `evidence_type=dast_scan`, alerts bucketed by risk | matches |
| Parse YAML/JSON attestations | `parsers/attestation.py` | `examples/sample_release/attestations/*.yaml` | attestation with unknown key → `extra='forbid'` raises | `evidence_type` derives from `kind` field | matches |
| 25 MB safety cap | `parsers/_common.py::read_bounded` | `tests/unit/test_parser_safety.py::test_oversize_file_hits_safety_cap`, `tests/unit/test_local_collector.py::test_oversized_artifact_is_reported_not_dropped` | large SARIF → raises `ArtifactTooLargeError` | reject > 25 MB | matches |

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
| Only recommended evidence is missing | `conditional` | `examples/sample_release/` with `artifact_attestation.yaml` removed | `conditional` (reproduced in `tests/unit/test_scoring.py::test_release_conditional_when_only_medium_gap`) |
| Only medium-criticality controls lack evidence | `conditional` | drop `threat_model.yaml` | `conditional` |
| A critical control lacks required evidence | `not_ready` | sample_release without `--attestations-dir` | `not_ready` (4 missing critical: `ORG-CODE-REVIEW`, `ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`) |
| Vulnerable lab scanned without attestations | `not_ready` | `examples/labs/01-core-saas-lab/` | `not_ready` (4 missing critical: `ORG-CODE-REVIEW`, `ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`) — re-validated 2026-05-17 against [`output/publication-2026-05-17/labs/01-core-saas-lab/`](../output/publication-2026-05-17/labs/01-core-saas-lab/) |
| Vulnerable lab with weaker SBOM coverage | `not_ready` | `examples/labs/04-data-batch-lab/` | `not_ready` (5 missing critical: the same four plus `SSDF-PS.3` because no SBOM attestation is present) |
| Vulnerable lab where `sca_scan` is present | `not_ready` | `examples/labs/06-industry-regulated-lab/` | `not_ready` (4 missing critical; one extra control met because `pip-audit` evidence raises `SSDF-PW.4` to `met`) |

## 5 · Determinism & stability promise

| Promise | Test | Expected | Obtained |
|---|---|---|---|
| Two runs on identical inputs produce identical `bundle.json` (after stripping `generated_at`, `evaluated_at`, `bundle_id`) | `tests/integration/test_determinism.py::test_sample_release_bundle_is_deterministic` | diff returns empty | matches |
| Artifact discovery order does not change the bundle | `tests/integration/test_determinism.py::test_sample_release_bundle_is_stable_across_artifact_reorder` | identical structural hash | matches |
| The structural hash holds under every profile | `tests/integration/test_determinism.py::test_structural_hash_is_stable_under_every_profile` | identical structural hash | matches |
| `compare` command reports zero deltas for identical bundles | `tests/integration/test_cli_more_commands.py::test_compare_emits_zero_delta_for_identical_bundles` | no improvements/regressions | matches |

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
