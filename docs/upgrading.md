# Upgrading

What changes for you between releases: verdicts, exit codes and outputs. One
section per release, newest first. The changelog lists every change; this page
lists only the ones that can change a result you already depend on.

## Unreleased

Opt-in catalogs and profiles follow their upstream sources. The default
catalog (`catalog.yaml`) and runs without `--profile` are unchanged, so their
bundles and structural digests stay the same.

- **`catalog-ssdf-1.2.yaml`**: adds `SSDF-PS.4` (recommended `test_result` and
  `rollback_plan`) and `SSDF-PO.6` (recommended `generic_attestation`), the two
  practices the SSDF 1.2 initial public draft adds. A release that was `ready`
  under this catalog is `conditional` until it supplies those types, so
  `--fail-on conditional` exits 1 for it. Neither control can make a release
  `not_ready`. The `SSDF-PS.3` and `SSDF-PW.6` descriptions now say what the
  draft changes and what is this project's policy; their evidence rules are
  unchanged. `catalog.sha256` changes.
- **`catalog-osps-baseline.yaml`**: re-pinned from v2025-02-25 to OSPS Baseline
  v2026.08.28. Adds `OSPS-SA-03.02` (recommended `threat_model`) and
  `OSPS-BR-02.01` (recommended `artifact_attestation`), with the same verdict
  effect as above. `OSPS-QA-07.01` now asks for a non-author human approval
  and says that code-review evidence does not tell bots from people.
  `catalog.sha256` changes.
- **`catalog-fedramp-cr26.yaml` and `--profile fedramp-20x`**: the CR26 pin
  moves from 2026.10.05.01 to 2026.10.13.01 (commit `a89d7847`).
  `metadata.fedramp.ruleset_version`, `metadata.fedramp.ruleset_commit`, the
  catalog descriptions and `catalog.sha256` change; evidence rules and verdicts
  do not. `--fedramp-class D` now logs a warning, on the console and as a JSON
  log event, that 20x Class D certifications are still being developed; the
  exit code and the bundle do not change.
- **`--profile cra-2026`**: `metadata.cra.srp_glossary_version` is `1.5` and
  `srp_glossary_date` is `2026-10-15` (were `1.4` and `2026-10-01`). The
  required SRP fields per stage are unchanged.
- **CRA context**: a new optional field, `operator_role` (`manufacturer` or
  `open_source_steward`). A steward context uses 11 December 2027 as the start
  of reporting obligations and cites Article 24(3); see
  [the profile page](evidence-profile-migration.md#cra-operator-context). A
  context without `operator_role` gives the same metadata and the same
  `canonical_context_sha256` as before. Collector 4.2.0 and earlier reject a
  context file that contains the field.
- Bundles produced with these catalogs or profiles get new structural digests.
  Re-pin `verify --expected` after regenerating them.
