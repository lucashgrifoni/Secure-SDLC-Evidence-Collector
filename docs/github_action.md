# Using the GitHub Action

The repository exposes a reusable composite action at its root
(`action.yml`) so any GitHub Actions workflow can call the collector
without installing Python locally.

## Quick start

```yaml
name: release-evidence

on:
  push:
    tags: ["v*.*.*"]

permissions:
  contents: read
  pull-requests: read
  actions: read

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Step 1 — produce raw artifacts with your own scanners.
      # Install your project and its test dependencies here as well.
      - id: scan
        run: |
          mkdir -p artifacts
          pip install "bandit[sarif]" cyclonedx-bom pytest
          # --exit-zero: findings must not abort the step before the
          # collector runs; their severities still reach the bundle.
          python -m bandit -r src -f sarif -o artifacts/bandit.sarif --exit-zero
          python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cdx.json
          # Record the test result instead of stopping here, so the
          # collector still runs; the last step re-raises it.
          python -m pytest --junitxml=artifacts/junit.xml && status=0 || status=$?
          echo "pytest-status=$status" >> "$GITHUB_OUTPUT"

      # SCA: the collector reads SARIF, not pip-audit's native JSON, so
      # use a scanner that writes SARIF (Trivy here).
      - uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # 0.36.0
        with:
          scan-type: fs
          scanners: vuln
          format: sarif
          output: artifacts/trivy-deps.sarif

      # Step 2 — assemble the evidence bundle
      - id: collect
        uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
        with:
          application: "payments-api"
          release-id: ${{ github.ref_name }}
          artifacts-dir: artifacts
          attestations-dir: attestations
          # No `pull-request:` here: a tag push carries no PR number
          # (`github.event.number` is empty outside `pull_request` events),
          # so ORG-CODE-REVIEW has to come from a `code_review` attestation
          # in `attestations/`. See "Collecting PR evidence" below.
          fail-on: not_ready

      - name: Upload bundle
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sdlc-evidence
          path: output/sdlc-evidence

      # Step 3 — fail the job if the tests failed.
      - name: Re-raise the test result
        if: steps.scan.outputs.pytest-status != '0'
        run: |
          echo "pytest exited ${{ steps.scan.outputs.pytest-status }}"
          exit 1
```

The scan step records pytest's exit status instead of stopping, so a failing
test run does not skip the collector: the JUnit file records the failures and
the bundle reflects them. Failing tests only make the release `conditional`
(the test-result control is not met), and with `fail-on: not_ready` a
`conditional` release exits `0`, so without the last step the job would end
green with failing tests. Re-raising the recorded status keeps the test
failure visible; `fail-on: conditional` is the stricter alternative.

### First runs: observe mode

Expect the first runs to end `not_ready`. The default catalog has five
critical controls, and four of them (code review, release approval, rollback
plan and artifact signature) are satisfied only by attestations you write,
or for code review by `pull-request:` on a pull request. Until they exist the
collector exits `2` and the job fails.

To see the report before enforcing anything, run the action in observe mode
with `fail-on: none`. The verdict is still computed and written to the
outputs, the bundle and the job summary, and the step passes. It fails only
when the collector could not run at all (exit `3`). Observe mode is a setting
of the Action and the reusable workflow; the CLI itself has no `none` value.

```yaml
on:
  workflow_dispatch:
  pull_request:

# ...same steps as above, with:
      - id: collect
        uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
        with:
          application: "payments-api"
          release-id: pr-${{ github.event.number }}
          artifacts-dir: artifacts
          fail-on: none
```

The job summary lists the missing critical evidence (what makes the release
`not_ready`) apart from the missing high evidence (what makes it
`conditional`). Add the missing evidence, then switch to `fail-on: not_ready`
or `fail-on: conditional` on the release trigger.

### Collecting PR evidence

The PR approval collector needs a pull request number, and only
`pull_request` events provide one in `github.event.number`. Run the action on
pull requests to collect it:

```yaml
on:
  pull_request:

# ...same steps as above, with:
      - uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
        with:
          application: "payments-api"
          release-id: pr-${{ github.event.number }}
          artifacts-dir: artifacts
          pull-request: ${{ github.event.number }}
```

On a tag push, either look the merged PR number up yourself and pass it, or
record the review in a `code_review` attestation.

## Inputs

| Input | Required | Default | Notes |
|-------|----------|---------|-------|
| `application` | yes | — | |
| `release-id` | yes | — | Tag, semver, calver, etc. |
| `repository` | no | `github.repository` | |
| `commit-sha` | no | `github.sha` | |
| `branch` | no | source branch of a pull request, the pushed branch, or the default branch on a tag | Up to 4.2.0 the default was `github.ref_name`, which is the tag name on a tag push and `<number>/merge` on a pull request |
| `tag` | no | the pushed tag, empty otherwise | Forwarded as `--tag` |
| `pipeline-run-id` | no | `github.run_id` | Forwarded as `--pipeline-run-id`; set to `""` to omit |
| `build-id` | no | `github.run_id`-`github.run_attempt` | Forwarded as `--build-id`; set to `""` to omit |
| `environment` | no | `production` | |
| `artifacts-dir` | no | `artifacts` | Walked recursively. A directory that does not exist is skipped with a notice (the default value) or a warning (any other value) that names it |
| `attestations-dir` | no | `attestations` | YAML or JSON. Skipped the same way as `artifacts-dir` when missing |
| `pull-request` | no | — | Enables PR approval collector. An empty value is ignored, so `${{ github.event.number }}` only works on `pull_request` events |
| `workflow-run` | no | — | Enables workflow metadata collector. Only a run that concluded with `success` satisfies a control; the run executing the action is still in progress, so `${{ github.run_id }}` from the same job never does. Pass a finished run |
| `exceptions-dir` | no | — | Directory with waiver (exception) files |
| `catalog` | no | — | Your own controls YAML, **or** the bare name of a bundled catalog |
| `artifact-root` | no | `github.workspace` | Paths recorded relative to this; set to `""` to keep absolute paths |
| `profile` | no | `none` | `none` / `cra-2026` / `fedramp-20x` |
| `cra-context` | no | — | CRA operator context JSON, forwarded as `--cra-context`; requires `profile: cra-2026` |
| `fedramp-class` | no | — | CR26 class `A`–`D`, forwarded as `--fedramp-class`; requires `profile: fedramp-20x`. Metadata only: it does not change which controls are evaluated |
| `risk-mode` | no | `off` | `off` / `epss-weighted`. The Action does not run `enrich`, so on its own this only records the mode; the verdict and exit code stay presence-based. Run `sdlc-evidence enrich` on the bundle in a later step to apply it (see [limitations §14](limitations.md)) |
| `epss-percentile-threshold` | no | — | Only meaningful with `risk-mode: epss-weighted` |
| `output-dir` | no | `output/sdlc-evidence` | |
| `fail-on` | no | `not_ready` | `not_ready` / `conditional` / `none`. With the default, a `conditional` release exits **0**. `ready` is accepted and behaves like `conditional`. `none` is observe mode (see above) |
| `python-version` | no | `3.12` | Dependencies are hash-locked on 3.12 and 3.13 (see [Installation](#installation)) |
| `version` | no | — | Git ref of the collector to install instead of the Action's own copy. A plain release number such as `4.2.0` is read as the tag `v4.2.0` |

The six bundled catalogs can be selected by name, without a path:
`catalog.yaml`, `catalog-ssdf-1.2.yaml`, `catalog-ai.yaml`,
`catalog-fedramp-cr26.yaml`, `catalog-osps-baseline.yaml` and the deprecated
`catalog-fedramp-20x-ksi.yaml`, whose IDs are not official FedRAMP KSIs.

The [reusable workflow](reusable_workflow.md) runs the collector in a job of
its own. Its inputs, outputs and defaults, and how they differ from this
Action and the GitLab component, are listed there.

### Release lineage

The bundle's `release` block records the branch, the tag, the pipeline run
and the build. On a tag push the Action records the tag in `tag` and the
repository's default branch in `branch`; on a pull request it records the
source branch. `pipeline-run-id` and `build-id` tie each bundle to the
workflow run that produced it. They are part of the bundle's structural
digest, so two runs of the same release no longer produce the same digest.
Set both to `""` when you compare digests across runs.

### Applying waivers in CI

```yaml
- uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
  with:
    application: payments-api
    release-id: ${{ github.ref_name }}
    artifacts-dir: artifacts
    exceptions-dir: .security/waivers
```

Unlike the evidence directories, a configured `exceptions-dir` that does not
exist is **not** skipped silently — losing an approved, time-bound exception
would change the verdict without a word, so the collector reports the bad path
in the collection warnings and in the bundle's `collection_errors` instead.
When another input directory exists, the run still writes the bundle and
exits with the verdict, not `3`; fail a later step on a non-zero
`collection-errors` output if a missing waiver directory must stop the job.
When the waiver directory is the only input left (the evidence directories
were skipped because they do not exist), nothing can be collected: the run
exits `3` and writes no bundle.

## Outputs

- `bundle-path`: absolute path of the generated `bundle.json`.
- `release-status`: `ready`, `conditional` or `not_ready`.
- `coverage-score`: integer from 0 to 100.
- `report-path`: absolute path of the generated `report.md`.
- `controls-total`, `controls-met`, `controls-partial`, `controls-missing`,
  `controls-waived`, `controls-not-applicable`: control counts from the bundle
  summary, so a later step can branch on them without parsing `bundle.json`.
  The last five add up to `controls-total`.
- `collection-errors`: how many supplied inputs could not be read (the
  bundle's `collection_errors`).

All outputs are empty strings when the collector wrote no bundle, for example
when it could not run (exit `3`). A later step with `if: always()` should
check `bundle-path != ''` before reading the others.

### Gaps in code scanning

`sdlc-evidence sarif` turns the unmet controls into a SARIF log (see
[SARIF output](sarif.md)). After the Action, read the bundle from its
`bundle-path` output, and run the upload also when the collector step
failed, because a `not_ready` release is the one with gaps to show:

```yaml
      - id: collect
        uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
        with:
          application: "payments-api"
          release-id: ${{ github.ref_name }}

      - name: Export gaps as SARIF
        if: always() && steps.collect.outputs.bundle-path != ''
        env:
          BUNDLE_PATH: ${{ steps.collect.outputs.bundle-path }}
        run: sdlc-evidence sarif "$BUNDLE_PATH" -o gaps.sarif

      - uses: github/codeql-action/upload-sarif@<pinned-sha>
        if: always() && steps.collect.outputs.bundle-path != ''
        with:
          sarif_file: gaps.sarif
          category: release-evidence
```

The upload step needs `security-events: write`.

## Job summary

The action appends a short table to the job summary page: release status,
coverage and the control counts. Below it, the evidence missing from critical
controls (what makes the release `not_ready`) is listed apart from the
evidence missing from high controls (what makes it `conditional`), then up to
ten collection warnings (inputs that were supplied but could not be read),
and the path of `report.md`. The application name, release id, paths and
warnings come from your inputs and files, so they are shown as code spans
that cannot close themselves or start a new line. The full report stays in
`report.md`; upload the output directory with `actions/upload-artifact` to
keep it after the job.

## Installation

Without `version`, the Action installs its own copy of the collector. On
Python 3.12 and 3.13 the third-party dependencies come from the hash-locked
files shipped with the Action (`.github/requirements/pip.txt` and
`runtime.txt`, installed with `--require-hashes`), and the collector itself is
installed from the Action's source with `--no-deps`, so two runs of the same
Action tag use the same dependency versions. On other Python versions the
Action prints a notice and resolves the version ranges from `pyproject.toml`.
The packages go into the Python that the Action's `setup-python` step selects,
which later steps of the job also use.

With `version`, the collector and its dependencies are installed from that git
ref without hash locks.

Every Python call in the Action runs with `python -P`, so a module in the
checked-out repository (the working directory) is never imported in place of
the collector's own.

## Attesting the evidence

To have GitHub sign the evidence as an attestation on your release
artifact, add `actions/attest` after the collector. Give it the predicate
payload, not the whole in-toto Statement: `actions/attest` builds the
Statement itself, so passing `sdlc-evidence statement` output as the
predicate would nest one Statement inside another.

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write

steps:
  - id: evidence
    uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.2.0 # x-release-please-version
    with:
      application: payments-api
      release-id: ${{ github.ref_name }}
      artifacts-dir: artifacts

  - id: predicate
    env:
      BUNDLE_PATH: ${{ steps.evidence.outputs.bundle-path }}
    run: |
      sdlc-evidence statement "$BUNDLE_PATH" -o statement.intoto.json
      jq '.predicate' statement.intoto.json > predicate.json
      echo "type=$(jq -r '.predicateType' statement.intoto.json)" >> "$GITHUB_OUTPUT"

  - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
    with:
      subject-path: dist/*.whl
      predicate-type: ${{ steps.predicate.outputs.type }}
      predicate-path: predicate.json
```

`subject-path` names what you ship. Anyone can then check the attestation
with `gh attestation verify <file> --repo <owner>/<repo> --predicate-type
<type>`. The `action-self-test` workflow in this repository runs the same
steps on the sample release.

## Permissions

The composite action passes the workflow token to the collector only when
`pull-request` or `workflow-run` is set, the two inputs that call the GitHub
API; otherwise the collector runs with an empty `GITHUB_TOKEN`. Minimum
permissions for the happy path:

```yaml
permissions:
  contents: read
  pull-requests: read
  actions: read
```

No token is logged by the collector.

## Docker image

An OCI image is also provided (`Dockerfile` in the repo root). It runs as
a non-root UID (`10001:10001`) and expects evidence volumes mounted into
`/workspace`. The output mount must be writable by the user the container
runs as. On a Linux host a fresh `output/` directory belongs to you (or to
root, if Docker creates it), not to UID 10001, and the run fails with
`PermissionError` (exit `3`). Create the directory first and run the
container with your own UID and GID:

```bash
docker build -t sdlc-evidence:local .
mkdir -p output
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/artifacts:/workspace/artifacts:ro" \
  -v "$PWD/attestations:/workspace/attestations:ro" \
  -v "$PWD/output:/workspace/output" \
  sdlc-evidence:local run \
    --application payments-api \
    --repository acme/payments-api \
    --release-id 2026.04.10 \
    --commit-sha abcdef1234567890 \
    --artifacts-dir /workspace/artifacts \
    --attestations-dir /workspace/attestations \
    --output-dir /workspace/output
```

Alternatively keep the image's UID and give it the directory
(`sudo chown 10001:10001 output`). Docker Desktop on Windows and macOS
maps bind-mount ownership, so the command also works there without
`--user`.
