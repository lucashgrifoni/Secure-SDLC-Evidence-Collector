# Using the reusable workflow

`.github/workflows/reusable-evidence-collection.yml` is a reusable GitHub
Actions workflow: one `uses:` line in a job of your workflow runs the
collector in a job of its own and uploads the bundle as an artifact. Use the
[composite Action](github_action.md) instead when the collector should run
as a step inside one of your jobs, next to the scanner output it reads.

## Usage

The reusable workflow runs on a fresh runner. Files written by your earlier
jobs are not there, so upload the scanner output as an artifact and name it
in `artifact-name`; the workflow downloads it into `artifacts-dir` before it
collects.

```yaml
on:
  push:
    tags: ["v*.*.*"]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      # ... run your scanners into scanner-output/ ...
      - uses: actions/upload-artifact@v4
        with:
          name: scanner-output
          path: scanner-output/

  evidence:
    needs: scan
    uses: lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/reusable-evidence-collection.yml@v4.2.0 # x-release-please-version
    with:
      application: my-app
      repository: ${{ github.repository }}
      release-id: ${{ github.ref_name }}
      artifact-name: scanner-output
      artifacts-dir: scanner-output
      attestations-dir: attestations
      collector-version: "4.2.0" # x-release-please-version

  after:
    needs: evidence
    if: ${{ !cancelled() }}
    runs-on: ubuntu-24.04
    steps:
      - env:
          RELEASE_STATUS: ${{ needs.evidence.outputs.release-status }}
        run: echo "release status $RELEASE_STATUS"
```

The ref in `uses:` pins the workflow file. `collector-version` pins the
package it installs from PyPI; see [Collector version](#collector-version).
`attestations-dir`, `exceptions-dir` and `cra-context` are read from your
checked-out repository, so those files have to be committed; only
`artifact-name` brings files from another job.

## Outputs

| Output | Meaning |
|--------|---------|
| `release-status` | `ready`, `conditional` or `not_ready` |
| `coverage-score` | Integer from 0 to 100 |
| `controls-total` | Controls in the catalog the bundle was evaluated against |
| `controls-met`, `controls-partial`, `controls-missing`, `controls-waived`, `controls-not-applicable` | Control counts; they add up to `controls-total` |
| `collection-errors` | Inputs that were supplied but could not be read (the bundle's `collection_errors`) |

All outputs are empty when the collector wrote no bundle, for example when
none of the input directories exists (exit `3`). The bundle, `report.md` and
`summary.html` are uploaded as the `secure-sdlc-evidence` artifact.

## Failure behavior

- `fail-on` decides which verdict fails the job: `not_ready` (default; a
  `conditional` release passes), `conditional`, or `none`. `ready` is
  accepted and behaves like `conditional`.
- `fail-on: none` is observe mode. The verdict is reported in the outputs
  and the bundle is uploaded, and the job passes. It still fails when the
  collector could not run at all (exit `3`). Use it for the first runs, while
  the evidence is incomplete and a `not_ready` verdict is expected.
- The bundle and report are uploaded also when the job fails, so a
  `not_ready` release leaves its report behind. When the collector wrote
  nothing, the upload step only warns.

## Harden-Runner and telemetry

The job starts with StepSecurity Harden-Runner in audit mode. Harden-Runner
records the job's network connections, processes and file writes and sends
them to StepSecurity. On private repositories it needs a paid StepSecurity
plan and otherwise adds a notice to the job summary. Set
`harden-runner: false` to skip the step. The default stays `true` in 4.x.

## Collector version

With `collector-version` empty, the workflow installs the latest release
from PyPI and prints a notice. Pin it to an exact release so two runs of the
same workflow use the same collector. The install cannot be hash-locked: the
lock files of this project do not exist in your repository.

`install-from-checkout: true` installs the collector from the checked-out
repository with this project's hash locks. It exists for this project's own
self-test (`action-self-test.yml`); leave it `false`.

## Inputs across the three surfaces

The composite Action, this workflow and the GitLab CI/CD component accept
mostly the same inputs. The table lists every input of each surface with its
default. `required` means the input has no default, and `—` means the surface
does not have the input. `tests/unit/test_surface_parity.py` compares this
table with `action.yml`, the workflow and
`examples/gitlab-component/templates/collect.yml`, so it fails when a surface
changes and this page does not.

| Input | Action | Reusable workflow | GitLab component | Notes |
|-------|--------|-------------------|------------------|-------|
| `application` | required | required | `$CI_PROJECT_NAME` | The component defaults to the project name |
| `repository` | `${{ github.repository }}` | required | `$CI_PROJECT_PATH` | Inside a reusable workflow the caller passes it explicitly |
| `release-id` | required | required | `$CI_COMMIT_REF_NAME` | The component defaults to the branch or tag name |
| `commit-sha` | `${{ github.sha }}` | `${{ github.sha }}` | — | The component always records `CI_COMMIT_SHA` |
| `branch` | `${{ github.head_ref \|\| (github.ref_type == 'branch' && github.ref_name) \|\| github.event.repository.default_branch \|\| github.ref_name }}` | `${{ github.head_ref \|\| (github.ref_type == 'branch' && github.ref_name) \|\| github.event.repository.default_branch \|\| github.ref_name }}` | — | The component derives the same value from `CI_COMMIT_BRANCH`, the merge request source branch or `CI_DEFAULT_BRANCH` |
| `tag` | `${{ github.ref_type == 'tag' && github.ref_name \|\| '' }}` | `${{ github.ref_type == 'tag' && github.ref_name \|\| '' }}` | — | The component records `CI_COMMIT_TAG` |
| `pipeline-run-id` | `${{ github.run_id }}` | `${{ github.run_id }}` | — | The component records `CI_PIPELINE_ID` |
| `build-id` | `${{ github.run_id }}-${{ github.run_attempt }}` | `${{ github.run_id }}-${{ github.run_attempt }}` | — | The component records `CI_JOB_ID` |
| `environment` | `production` | `production` | — | The component has no input and records the collector default, `production`, on every pipeline |
| `artifact-name` | — | `""` | — | Only the reusable workflow runs in a separate job; the component receives earlier jobs' artifacts from GitLab |
| `artifacts-dir` | `artifacts` | `artifacts` | `artifacts` | The Action skips a missing directory with a notice or warning; the others pass it to the collector |
| `attestations-dir` | `attestations` | `""` | `""` | The Action looks in `attestations` by default; the others read attestations only from a directory you name |
| `exceptions-dir` | `""` | `""` | `""` | |
| `catalog` | `""` | `""` | `""` | The reusable workflow accepts only bundled catalog names; the Action and the component also accept a path |
| `pull-request` | `""` | — | — | Needs the workflow token, which the reusable workflow does not use |
| `workflow-run` | `""` | — | — | Needs the workflow token, which the reusable workflow does not use |
| `artifact-root` | `${{ github.workspace }}` | — | — | The component always passes `CI_PROJECT_DIR` |
| `profile` | `none` | `none` | `none` | |
| `cra-context` | `""` | `""` | `""` | |
| `fedramp-class` | `""` | `""` | `""` | |
| `risk-mode` | `off` | `off` | — | The component does not expose it |
| `epss-percentile-threshold` | `""` | — | — | Only the Action exposes it |
| `output-dir` | `output/sdlc-evidence` | — | — | The reusable workflow and the component write `release-evidence/` |
| `fail-on` | `not_ready` | `not_ready` | `conditional` | The component fails on a `conditional` release by default; the GitHub surfaces pass it. `none` (observe mode) exists only on the GitHub surfaces |
| `python-version` | `3.12` | `3.12` | — | The component runs a pinned `python:3.12` image |
| `version` | `""` | — | — | Empty installs the Action's own copy with hash-locked dependencies; otherwise a git ref of this repository |
| `collector-version` | — | `""` | `4.2.0` | Empty installs the latest PyPI release; the component pins one |
| `harden-runner` | — | `true` | — | Only the reusable workflow adds Harden-Runner to your job; see above |
| `install-from-checkout` | — | `false` | — | For this project's self-test |
| `stage` | — | — | `test` | GitLab only |
| `job-name` | — | — | `sdlc-evidence` | GitLab only |

The default gate differs between GitLab and GitHub: with the same evidence,
a release that is `conditional` (a high control such as a scanner is
missing or failed) fails the component job and passes the Action and this
workflow. Set `fail-on: conditional` on the GitHub surfaces to match the
component.
