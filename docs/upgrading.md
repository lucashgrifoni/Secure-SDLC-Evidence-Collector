# Upgrading

Changes that can alter what a pipeline sees: verdicts, exit codes, outputs,
recorded bundle content and CI surface behavior. The newest release is at the
top. [CHANGELOG.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/CHANGELOG.md)
lists every change. The 4.0.0 digest migration is in
[evidence profile migration](evidence-profile-migration.md); the 3.0.0 changes
are under "Migrating to 3.0.0" in the
[README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector#migrating-to-300).

## Unreleased

### GitHub Action

- Bundles record the release lineage. `tag` is the pushed tag,
  `pipeline_run_id` is `github.run_id` and `build_id` is
  `github.run_id`-`github.run_attempt`. The `branch` default is the pull
  request's source branch, the pushed branch, or the repository's default
  branch on a tag push; it used to be `github.ref_name`, the tag name on a
  tag push and `<number>/merge` on a pull request. These fields are inside the
  structural digest, so the digest of an Action-produced bundle changes and
  now differs from run to run. Set `pipeline-run-id: ""` and `build-id: ""`,
  and `branch` explicitly, to keep comparing digests across runs. The
  verdict does not change.
- On Python 3.12 and 3.13 the Action installs its dependencies from the
  hash locks it ships (`--require-hashes`), so exact versions land in the
  job's Python instead of the newest versions in range. Other Python versions
  keep the old behavior and print a notice.
- The collector process gets `GITHUB_TOKEN` only when `pull-request` or
  `workflow-run` is set. Otherwise the variable is empty for that step, also
  when the job sets it.
- `fail-on: none` is new: observe mode. Verdict exits `1` and `2` become `0`;
  exit `3` still fails the step. The existing values behave as before.
- A missing `artifacts-dir` or `attestations-dir` is still skipped, now with
  a notice (default value) or a warning (any other value) naming it.
- `version: 4.2.0` is read as the tag `v4.2.0`. It used to point at a ref
  that does not exist and the install failed.
- New outputs: `controls-waived`, `controls-not-applicable` and
  `collection-errors`. The job summary changed: a Not applicable column,
  missing critical and missing high evidence on separate lines, collection
  warnings, and the path of `report.md`.
- Python runs with `-P`, so modules in the working directory are no longer
  importable from the Action's steps.
- On macOS runners the outputs are set on every run that wrote a bundle.
  They used to be empty when the collector finished within the second it
  started in, because the bash that macOS ships compares file times in whole
  seconds.

### Reusable workflow

- The bundle and report are uploaded also when the run fails, including a
  `not_ready` release. Nothing is uploaded when the run wrote no bundle
  (exit `3`, or a failed earlier step); the job has already failed by then.
- New inputs: `fail-on` (default `not_ready`, the value that was hard-coded,
  plus `none`), `environment` (default `production`, the value recorded
  before), `artifact-name` to download scanner output from an earlier job,
  `tag`, `pipeline-run-id`, `build-id`, `harden-runner` (default `true`) and
  `install-from-checkout` (default `false`). The `branch` default and the
  recorded lineage changed as for the Action above.
- New outputs: `release-status`, `coverage-score`, the control counts and
  `collection-errors`.
- An empty `collector-version` prints a notice; it still installs the latest
  release.
- Python runs with `-P` here too, so modules in the caller's checkout are no
  longer importable from the workflow's steps.
- The job runs on `ubuntu-24.04` instead of `ubuntu-latest`.

### GitLab

- `examples/gitlab-ci/secure-sdlc-evidence.yml` is deprecated in favor of
  the CI/CD Catalog component. It behaves as before.
- GitLab Security Reports (schema 15) are read as scan evidence. A
  `sast`, `secret_detection`, `dependency_scanning`, `container_scanning`
  or `dast` report in `--artifacts-dir` becomes one `sast_scan`,
  `secrets_scan`, `sca_scan` or `dast_scan` record; up to 4.2.0 these files
  were listed as matching no parser. A pipeline that already supplies them
  gets new evidence, so its verdict can change in either direction: a
  control that was missing can now be met, or fail on a critical or high
  finding, on any detected secret, or on a report whose `scan.status` is
  `failure`. Other GitLab report types are still listed as matching no
  parser. `sdlc-evidence plugins` lists a new built-in parser, `gitlab`.

### Scanner results are read as the scanner reported them

Verdicts can get stricter on unchanged scanner files. The sample release
is unaffected: its bundle digest and its `ready` verdict stay the same. A
bundle built from a scanner file that one of these changes touches gets a
different digest, so refresh any `verify --expected` pin for it.

- SARIF results with no `level` take the level of the rule they reference
  (`defaultConfiguration.level`), then `warning`, as SARIF 2.1.0 §3.27.10
  says. Real Semgrep, Gitleaks and KICS output is written this way, so an
  `ERROR` rule hit that used to count as medium now counts as high and
  fails `sast_scan`. A rule's `security-severity` can raise a bucket.
  Results whose `kind` is not `fail` now count as info.
- A SARIF run whose invocation reports `executionSuccessful: false` is
  `invalid` and no longer satisfies its control.
- An open result in a `secrets_scan` fails it, whatever its level, unless
  its SARIF `kind` is `pass`, `notApplicable` or `informational`. This
  covers secret scanner SARIF (Gitleaks and others). Any finding of the
  secret class in a native Trivy JSON report fails it too. The finding
  counts keep the scanner's level.
- Checkov, KICS, tfsec and Terrascan SARIF is `iac_scan` instead of
  `sast_scan`. tfsec is matched by the driver name it writes, `defsec`. A
  release that relied on one of these alone for SSDF-PW.7 now shows that
  control as missing; add a SAST scanner. Their evidence ids start with
  `iac-` instead of `sast-`.
- SARIF results with only `accepted` (or status-less) suppressions, such
  as `# nosemgrep` lines, are no longer counted as findings. The number
  is recorded in `metadata.suppressed_count` and named in the summary.
- A SARIF run with no `results` array, or with error-level tool
  notifications, is recorded at `low` confidence with a warning on the
  console and in NDJSON logs; its status does not change.
- JUnit counts are the larger of each suite attribute and the matching
  `<testcase>` elements, and negative attributes read as 0. A report
  whose suite omits `failures` but holds a failing test case now fails
  `test_result`.
- OSV-Scanner `groups` are honoured: aliases of one issue count as one
  finding, so `total_findings` can go down. CVE ids are unchanged. A group
  whose members carry no usable severity takes the group's `max_severity`,
  so a finding that used to count as medium can now count as high or
  critical and fail `sca_scan`.
- A clean native Trivy report, which has no `Results` key, is recognised
  instead of being listed as matching no parser. It still produces no
  evidence.

### OSCAL export

- Controls in the OSCAL Catalog that `sdlc-evidence oscal` writes no longer
  carry a `uuid`. The OSCAL 1.1.2 catalog schema does not allow one on a
  control, so strict validators rejected every catalog the command wrote.
  Identify a control by its `id`, or by the `control_id` property, which hold
  the same values as before. The catalog's own `uuid` and the Assessment
  Results export are unchanged.

### Opt-in catalogs and profiles

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
  effect as above. `OSPS-QA-07.01` now asks for a non-author human approval.
  Code-review evidence cannot show that an approver is a person, so the
  control also recommends a `generic_attestation` in which a reviewer states
  that at least one approver is a person. Without it the control is `partial`
  (it was `met` when `code_review` and `pr_metadata` were both supplied), which
  makes the release `conditional`, never `not_ready`. `catalog.sha256` changes.
- **GitHub pull request evidence** (`run --pull-request`): when an
  approval on the head commit comes from a GitHub App bot account, the
  `code_review` record gets `metadata.bot_approvals` with the count and the
  run logs a warning, on the console and as a JSON log event. The approval
  still counts, so the evidence status and every verdict under the default
  catalog are unchanged. A record with no bot approval has no such key and
  keeps its digest. Machine user accounts are ordinary user accounts and are
  not detected.
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
  of reporting obligations and cites Article 24(3). A steward incident context
  names the Article 24(3) condition (the incident affects systems the steward
  provides for development) in `metadata.cra.incident_scope` with status
  `not_assessed`; the profile does not decide it. See
  [the profile page](evidence-profile-migration.md#cra-operator-context). A
  context without `operator_role` gives the same metadata and the same
  `canonical_context_sha256` as before. Collector 4.2.0 and earlier reject a
  context file that contains the field.
- Bundles produced with these catalogs or profiles get new structural digests.
  Re-pin `verify --expected` after regenerating them.

### CLI help text

Only the `--help` output changes. Arguments, options, exit codes and outputs
are the same.

- The usage line of every command that takes a positional argument names it
  explicitly: `BUNDLE_PATH` for `verify`, `enrich`, `vex`, `statement`, `guac`
  and `sarif`, `BEFORE AFTER` for `compare`, `PATHS...` for
  `exceptions validate` and `DIRECTORY` for `exceptions list`. With Typer 0.27
  the usage line used to show the lower-case parameter name in braces
  (`{bundle_path}`); it now shows `{BUNDLE_PATH}`, where the braces are how
  Typer 0.27 marks a required argument. Update any test or wrapper that
  matches the help text.
- `bundle --help` says that `bundle` is a partial alias of `evaluate` and
  names the options it does not accept.
- `run --help` describes `--exceptions-dir` as repeatable and `--catalog` as
  "a path, or the bare name of a bundled catalog", as `evaluate --help`
  already did.
- `statement --help` describes the `witness` variant as a
  `witness.dev`-namespaced predicate URI that has not been tested with
  `witness verify`.

## 4.2.0

Four behaviours change for pipelines that worked on 4.1.x. The sample release
still hashes to `e859f475…`, the structural digest it has had since 4.0.0.

| Change | Effect on an unchanged pipeline | What to do |
|---|---|---|
| Waiver and attestation files refuse unknown keys | A misspelt or custom key used to be dropped. It is now a parse error that names the key. A refused attestation is a collection error, so the control it backed can go missing and the verdict can drop. A refused waiver no longer applies. | Remove the extra key. In an attestation, custom data can move under `metadata`; a waiver has no such field. `exceptions validate` reports waiver files before a release does. |
| `vex --consume` applies a consumed statement only to a product of this release | A supplier statement used to be applied by CVE id alone. A statement that names no product of this release is now skipped, listed in a warning, and counted in `skipped` on the `vex_emitted` event. | Pass your release's purl, CPE, CycloneDX ref or CSAF product id with `--product` (repeatable). The bundle's own `pkg:generic` id always counts. Matching rules: [limitations §16](limitations.md). |
| `run` with no evidence source exits `3` | `run` with no input directory, no `--pull-request` and no `--workflow-run` used to produce a `not_ready` bundle. It now exits `3` and writes no bundle. | Make sure the scan directories exist before `run`, or treat exit `3` as a pipeline error rather than a verdict. |
| `exceptions list` exits `3` on a bad directory | `exceptions list` used to exit `0` when a file could not be parsed or an exception id was defined twice. It now exits `3`, as `exceptions validate` does. | Fix or remove the file it names. |

Example: apply a supplier's OpenVEX to the release `pkg:pypi/requests@2.30.0`
component instead of letting it be skipped.

```bash
sdlc-evidence vex output/bundle.json --consume supplier.vex.json \
  --product pkg:pypi/requests@2.30.0
```
