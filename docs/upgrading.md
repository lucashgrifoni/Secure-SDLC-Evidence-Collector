# Upgrading

Changes that can alter what a pipeline sees: verdicts, exit codes, outputs,
recorded bundle content and CI surface behavior. The newest release is at the
top. `CHANGELOG.md` lists every change.

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
