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

      # Step 1 — produce raw artifacts with your own scanners
      - run: |
          mkdir -p artifacts
          pip install bandit[sarif] cyclonedx-bom pip-audit
          python -m bandit -r src -f sarif -o artifacts/bandit.sarif
          python -m cyclonedx_py environment --of JSON -o artifacts/sbom.cdx.json
          python -m pytest --junitxml=artifacts/junit.xml

      # Step 2 — assemble the evidence bundle
      - id: collect
        uses: LucasGrifoni/secure-sdlc-evidence-collector@v1.0.0
        with:
          application: "payments-api"
          release-id: ${{ github.ref_name }}
          artifacts-dir: artifacts
          attestations-dir: attestations
          pull-request: ${{ github.event.number }}
          fail-on: not_ready

      - name: Upload bundle
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sdlc-evidence
          path: output/sdlc-evidence
```

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
| `pull-request` | no | — | Enables PR approval collector |
| `workflow-run` | no | — | Enables workflow metadata collector |
| `catalog` | no | — | Custom controls YAML |
| `output-dir` | no | `output/sdlc-evidence` | |
| `fail-on` | no | `not_ready` | `ready` / `conditional` / `not_ready` |
| `python-version` | no | `3.12` | |
| `version` | no | — | Git ref of the collector to install |

## Outputs

- `bundle-path` — absolute path of the generated `bundle.json`.
- `release-status` — `ready` / `conditional` / `not_ready`.
- `coverage-score` — 0–100 integer.

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
`/workspace`:

```bash
docker build -t sdlc-evidence:1.0.0 .
docker run --rm \
  -v "$PWD/artifacts:/workspace/artifacts:ro" \
  -v "$PWD/attestations:/workspace/attestations:ro" \
  -v "$PWD/output:/workspace/output" \
  sdlc-evidence:1.0.0 run \
    --application payments-api \
    --repository acme/payments-api \
    --release-id 2026.04.10 \
    --commit-sha abcdef1234567890 \
    --artifacts-dir /workspace/artifacts \
    --attestations-dir /workspace/attestations \
    --output-dir /workspace/output
```
