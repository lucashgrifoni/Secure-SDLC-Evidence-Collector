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

### Reusable workflow

- The bundle and report are uploaded also when the run fails, including a
  `not_ready` release; with no bundle the upload step warns instead of
  failing.
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
- The job runs on `ubuntu-24.04` instead of `ubuntu-latest`.

### GitLab

- `examples/gitlab-ci/secure-sdlc-evidence.yml` is deprecated in favor of
  the CI/CD Catalog component. It behaves as before.
