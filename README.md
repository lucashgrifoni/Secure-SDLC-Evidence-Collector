# Secure SDLC Evidence Collector

Collects the evidence a release already produces and tells you whether it proves a minimum Secure SDLC process: `ready`, `conditional` or `not_ready`.

[![CI](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/github-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/github-ci-cd.yml)
[![Security CI](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/security-ci-cd.yml/badge.svg)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/security-ci-cd.yml)
[![PyPI](https://img.shields.io/pypi/v/secure-sdlc-evidence-collector)](https://pypi.org/project/secure-sdlc-evidence-collector/)
![Python 3.12 & 3.13](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue)
![License Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-green)
[![Cosign signing configured](https://img.shields.io/badge/release%20signing-cosign%20keyless%20(configured)-9cf)](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows/publish-pypi.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15519/badge)](https://www.bestpractices.dev/projects/15519)

## At a Glance

`sdlc-evidence` reads the output of the tools you already run (scanners, SBOM generators, test runners, code review, attestations, release approvals) and evaluates it against a control catalog mapped to NIST SSDF and OWASP SAMM. It writes one auditable bundle per release and an exit code your pipeline can gate on.

| Current release | Default catalog | Outputs | Python |
|---|---|---|---|
| v4.3.1 <!-- x-release-please-version --> | 13 controls | `bundle.json`, `report.md`, `summary.html` | 3.12+ |

Use it when an auditor, a release manager or an AppSec lead asks "prove this release is ready" and the answer today is a checklist of screenshots. It is not a scanner and it does not certify compliance.

## Three Verdicts, One Exit Code

| Verdict | When | Exit code (default `--fail-on not_ready`) |
|---|---|---|
| `ready` | Every control is met, waived or not applicable | `0` |
| `conditional` | No critical control lacks required evidence, but at least one control is partial or missing, or supplied evidence was set aside | `0`, or `1` with `--fail-on conditional` |
| `not_ready` | A critical control lacks required evidence | `2` |

The verdict comes from the criticality of the gaps, never from the score. In the default catalog the critical controls are SBOM, code review, release approval, rollback plan and artifact signature. Scanners and tests are high, so a release without them is `conditional` and passes the default gate. Pass `--fail-on conditional` when that must stop the pipeline.

## Quickstart

```bash
python -m pip install secure-sdlc-evidence-collector
git clone https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector.git
cd Secure-SDLC-Evidence-Collector/examples/sample_release
sdlc-evidence run --application payments-api --repository acme/payments-api --release-id 2026.04.10 --commit-sha abcdef1234567890 --artifacts-dir artifacts --attestations-dir attestations --output-dir ../../output/sample_release
```

The same commands work in bash, zsh and PowerShell. The sample release ends `ready` with 13 of 13 controls met. The run writes, in `output/sample_release/` at the root of the clone:

- `summary.html` for people who decide on the release.
- `report.md` for review, with what to produce for each gap.
- `bundle.json` for automation: deterministic, with a structural SHA-256 that `sdlc-evidence verify` recomputes.

Drop `--attestations-dir` to see `not_ready` and the missing critical evidence. The [getting started guide](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/getting-started.md) takes the CLI, the GitHub Action, the GitLab component and the Docker image from install to first verdict.

## What It Does

- Reads SARIF from any scanner, native Trivy JSON, GitLab Security Reports, CycloneDX and SPDX SBOMs, OSV, JUnit, OWASP ZAP, and in-toto attestations (SLSA provenance, VSA, release attestations, PyPI and npm registry attestations).
- Reads approvals, rollback plans, threat models and other human evidence from YAML or JSON attestations.
- Reads GitHub pull request approvals and workflow runs on request (`--pull-request`, `--workflow-run`).
- Applies time-bound waivers with scope, owner and expiry, and keeps them visible in every output.
- Ships opt-in catalogs and profiles: SSDF 1.2, OSPS Baseline, EU CRA, FedRAMP 20x and AI evidence.
- Exports a bundle as OpenVEX, an in-toto Statement, SARIF for code scanning, OSCAL or a GUAC document.

## What It Does Not Do

- It does not scan code, containers or infrastructure. It reads the output of the tools that do.
- It does not decide compliance. `ready` means every control in the catalog has its evidence, not that the release is legally compliant.
- It does not judge severity or exploitability beyond what the scanner reported. That stays a human decision on top of the bundle.
- Known parser and classification limits are listed in [docs/limitations.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/limitations.md).

## Use It in CI

GitHub Action:

```yaml
- uses: lucashgrifoni/Secure-SDLC-Evidence-Collector@v4.3.1 # x-release-please-version
  with:
    application: payments-api
    release-id: ${{ github.ref_name }}
    artifacts-dir: artifacts
    attestations-dir: attestations
    fail-on: not_ready
```

Action reference: [docs/github_action.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/github_action.md). A [reusable workflow](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/reusable_workflow.md) and a [GitLab CI/CD Catalog component](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/examples/gitlab-component/README.md) are also available. The Action and the reusable workflow gate on `not_ready` by default; the GitLab component gates on `conditional`.

pre-commit, to validate waiver files and smoke-test the pinned release:

```yaml
repos:
  - repo: https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector
    rev: v4.3.1  # x-release-please-version
    hooks:
      - id: sdlc-evidence-validate-exceptions
      - id: sdlc-evidence-doctor
```

A third hook, `sdlc-evidence-schema`, fails the commit when a vendored copy of the bundle schema drifts; see `.pre-commit-hooks.yaml`.

## Exit Codes

| Code | Meaning |
|---:|---|
| 0 | `ready`, or a command that does not gate |
| 1 | `conditional`, subject to `--fail-on`; for `doctor`, a failed required check |
| 2 | `not_ready`; for `verify --expected`, a digest that does not match |
| 3 | The command could not run: bad input, unreadable file, failed validation |

Every command, option and exit code is in the [CLI reference](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/cli-reference.md). Under `--json-logs` every line is a JSON event; the events are listed in [docs/json-logs.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/json-logs.md).

## Upgrading

Upgrading to 4.3.0 keeps the CLI defaults, the exit codes and the default catalog's rules. Verdicts can still get stricter on unchanged scanner files, GitLab Security Reports become evidence, and bundles made by the Action and the reusable workflow get a new digest on every run. What to do about each change, release by release, is in [docs/upgrading.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/upgrading.md).

## Supply Chain Verification

Releases go to PyPI through Trusted Publishing. Wheel, sdist, release bundle and SBOM are signed with cosign keyless and logged in Sigstore Rekor, with SLSA Build Level 3 provenance. The multi-arch container image on `ghcr.io` is signed and SBOM-attested. The verification commands are under [Verifying signatures](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/index.md#verifying-signatures).

## Documentation Map

| Topic | Link |
|---|---|
| Documentation site | <https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/> |
| Getting started | [docs/getting-started.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/getting-started.md) |
| CLI reference | [docs/cli-reference.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/cli-reference.md) |
| Troubleshooting | [docs/troubleshooting.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/troubleshooting.md) |
| Bundle schema | [docs/bundle_schema.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/bundle_schema.md) |
| Limitations | [docs/limitations.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/limitations.md) |
| Comparison with alternatives | [docs/comparison.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/comparison.md) |
| Release readiness checklist | [docs/release-readiness.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/release-readiness.md) |
| Architecture decisions | [docs/adr/README.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/adr/README.md) |
| Roadmap | [docs/MATURITY_ROADMAP.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/docs/MATURITY_ROADMAP.md) |
| Repository wiki | [openwiki/quickstart.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/openwiki/quickstart.md) |
| Changelog | [CHANGELOG.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/CHANGELOG.md) |

## Repository Layout

| Path | Purpose |
|---|---|
| `src/evidence_collector/` | Python package: domain model, collectors, parsers, normalizers, control engine, scoring, exporters, CLI |
| `src/evidence_collector/controls/data/` | Bundled control catalogs |
| `examples/sample_release/` | Realistic evidence set used in the docs and tests |
| `examples/gitlab-component/` | GitLab CI/CD Catalog component |
| `action.yml` | GitHub Action |
| `tests/` | Unit, integration and property tests |
| `docs/` | Documentation site, ADRs and the published bundle schema |
| `.github/` | CI, security, release and Pages workflows |

## Development

```bash
make install-dev
make lint          # ruff
make typecheck     # mypy --strict on src/ and tests/
make test          # pytest with the coverage gate
make run-example   # build the sample bundle
```

Ideas waiting for a concrete need are collected in [Discussion #188](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/discussions/188).

## Contributing and Security

- Contribution guide: [CONTRIBUTING.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/CONTRIBUTING.md)
- Governance: [GOVERNANCE.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/GOVERNANCE.md)
- Vulnerability reporting: [SECURITY.md](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/SECURITY.md). Please do not open a public issue.
- Issues: <https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/issues>

## License

[Apache-2.0](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/LICENSE) © Lucas Henrique Grifoni. Since 4.0.0 the package also includes a BSD-2-Clause FIRST CVSS reference port; see [third-party notices](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/THIRD_PARTY_LICENSES.md).
