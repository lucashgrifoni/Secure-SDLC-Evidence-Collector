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
      - run: |
          mkdir -p artifacts
          pip install "bandit[sarif]" cyclonedx-bom pytest
          # --exit-zero: findings must not abort the step before the
          # collector runs; their severities still reach the bundle.
          python -m bandit -r src -f sarif -o artifacts/bandit.sarif --exit-zero
          python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cdx.json
          python -m pytest --junitxml=artifacts/junit.xml || true

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
        uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.0.0 # x-release-please-version
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
```

`python -m pytest ... || true` keeps a failing test run from skipping the
collector: the JUnit file records the failures and the bundle reflects them.

### Collecting PR evidence

The PR approval collector needs a pull request number, and only
`pull_request` events provide one in `github.event.number`. Run the action on
pull requests to collect it:

```yaml
on:
  pull_request:

# ...same steps as above, with:
      - uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.0.0 # x-release-please-version
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
| `branch` | no | `github.ref_name` | |
| `environment` | no | `production` | |
| `artifacts-dir` | no | `artifacts` | Walked recursively |
| `attestations-dir` | no | `attestations` | YAML or JSON |
| `pull-request` | no | — | Enables PR approval collector. An empty value is ignored, so `${{ github.event.number }}` only works on `pull_request` events |
| `workflow-run` | no | — | Enables workflow metadata collector. Only a run that concluded with `success` satisfies a control; the run executing the action is still in progress, so `${{ github.run_id }}` from the same job never does. Pass a finished run |
| `exceptions-dir` | no | — | Directory with waiver (exception) files |
| `catalog` | no | — | Your own controls YAML, **or** the bare name of a bundled catalog |
| `artifact-root` | no | `github.workspace` | Paths recorded relative to this; set to `""` to keep absolute paths |
| `profile` | no | `none` | `none` / `cra-2026` / `fedramp-20x` |
| `cra-context` | no | — | CRA operator context JSON, forwarded as `--cra-context`; requires `profile: cra-2026` |
| `fedramp-class` | no | — | CR26 class `A`–`D`, forwarded as `--fedramp-class`; requires `profile: fedramp-20x`. Metadata only: it does not change which controls are evaluated |
| `risk-mode` | no | `off` | `off` / `epss-weighted` |
| `epss-percentile-threshold` | no | — | Only meaningful with `risk-mode: epss-weighted` |
| `output-dir` | no | `output/sdlc-evidence` | |
| `fail-on` | no | `not_ready` | `ready` / `conditional` / `not_ready`. With the default, a `conditional` release exits **0** |
| `python-version` | no | `3.12` | |
| `version` | no | — | Git ref of the collector to install |

The six bundled catalogs can be selected by name, without a path:
`catalog.yaml`, `catalog-ssdf-1.2.yaml`, `catalog-ai.yaml`,
`catalog-fedramp-cr26.yaml`, `catalog-osps-baseline.yaml` and the deprecated
`catalog-fedramp-20x-ksi.yaml`, whose IDs are not official FedRAMP KSIs.
The reusable workflow accepts the same `cra-context` and `fedramp-class`
inputs.

### Applying waivers in CI

```yaml
- uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.0.0 # x-release-please-version
  with:
    application: payments-api
    release-id: ${{ github.ref_name }}
    artifacts-dir: artifacts
    exceptions-dir: .security/waivers
```

Unlike the evidence directories, a configured `exceptions-dir` that does not
exist is **not** skipped silently — losing an approved, time-bound exception
would change the verdict without a word, so the collector reports the bad path
in the collection warnings instead.

## Outputs

- `bundle-path`: absolute path of the generated `bundle.json`.
- `release-status`: `ready`, `conditional` or `not_ready`.
- `coverage-score`: integer from 0 to 100.
- `report-path`: absolute path of the generated `report.md`.
- `controls-total`, `controls-met`, `controls-partial`, `controls-missing`:
  control counts from the bundle summary, so a later step can branch on them
  without parsing `bundle.json`.

## Job summary

The action appends a short table to the job summary page: release status,
coverage, the control counts, and the critical evidence types that are
missing. The application name and release id come from your inputs, so they
are shown as code spans that cannot close themselves or start a new line.
The full report stays in `report.md`.

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
    uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.0.0 # x-release-please-version
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

The composite action reads `GITHUB_TOKEN` from the workflow. Minimum
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
