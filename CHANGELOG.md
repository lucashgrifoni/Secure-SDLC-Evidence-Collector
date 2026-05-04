# Changelog

All notable changes to this project are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-05-04

Maturity polish on top of 1.0.0. No behavioural changes to the bundle
schema, CLI surface, or GitHub Action contract.

### Added

- **PyPI publishing job** in `release.yml` using OIDC trusted publisher
  (no long-lived `PYPI_API_TOKEN`); gated to `refs/tags/v*` pushes and
  the `pypi` GitHub environment.
- **Schema dogfood step** in `github-ci-cd.yml`: every CI run now exports
  the bundle JSON Schema and validates the freshly generated sample
  bundle against it with `jsonschema`. Closes the self-attesting loop.
- **Targeted parser tests** for `parsers/exception.py` and
  `parsers/junit.py`: invalid ISO datetimes, unsupported datetime
  types, non-mapping `scope`, malformed/empty XML, legacy `skip`
  attribute, single `<testsuite>` root with malformed numeric
  attributes (exercises the `_parse_int` / `_parse_float` fallbacks).
- **Hardened security CI** (`security-ci-cd.yml`): Snyk Code, CodeQL,
  Trivy (vuln + misconfig + secrets), Dependency Review, Gitleaks,
  actionlint, Harden-Runner egress audit, and pinning third-party
  actions by immutable commit SHA with a trailing semantic-tag comment.

### Changed

- README badges now reflect the real numbers (123 tests passing,
  ~78% line+branch coverage) instead of the stale 1.0.0 figures.
- Repository now ships a top-level `.gitattributes` enforcing LF for
  text files. Stops Windows clones from emitting CRLF→LF warnings on
  the GitPage assets and ensures shell scripts and workflows stay
  Linux-compatible.

### Removed

- `.github/workflows/dependabot.yml` — that file was a misplaced
  template; the active Dependabot configuration lives at
  `.github/dependabot.yml`, where GitHub expects it.

## [1.0.0] — 2026-04-23

First stable release. The bundle schema, CLI surface, GitHub Action
inputs/outputs, and environment variables defined here are stable —
breaking them requires a major version bump.

### Added

- **GitLab / GitLab CI collector** mirroring the GitHub adapter
  (`GitLabCollector`) with MR approvals (incl. "last approval after
  last commit") and pipeline metadata. Reads `GITLAB_TOKEN` from the
  environment; never logs it.
- **OWASP SAMM secondary framework** mapped into the default control
  catalog (SAMM-DESIGN-TA-1, SAMM-IMPL-SB-2, SAMM-VERIF-ST-1)
  alongside NIST SSDF and org-internal controls.
- **DAST as first-class evidence** via the OWASP ZAP JSON parser and
  the new `dast_scan` type wired into SAMM-VERIF-ST-1.
- **Bundle comparison** command: `sdlc-evidence compare before.json
  after.json` returns coverage/confidence/status deltas and
  per-control improvements, regressions, additions, and removals
  (rendered as a Rich table or JSON via `--format json`).
- **JSON Schema export**: `sdlc-evidence schema --output schema.json`
  emits the canonical `EvidenceBundle` schema so third-party tools can
  validate bundles without importing Pydantic.
- **Exception subcommands**: `sdlc-evidence exceptions validate FILE`
  and `sdlc-evidence exceptions list DIR` for ops workflows around
  waivers.
- **Release workflow** (`.github/workflows/release.yml`) that runs all
  quality gates, builds wheel + sdist, produces the release evidence
  bundle, signs the artifacts and the bundle keyless with
  `cosign`+Sigstore, and publishes a GitHub Release carrying
  signatures, certificates, the bundle, the report, and the summary.
- **OSS governance files**: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `CODEOWNERS`, Dependabot config for Python / GitHub
  Actions / Docker, and GitHub issue + PR templates.

### Changed

- Control catalog expanded from 10 to 13 controls.
- `sample_release` fixture grew a ZAP baseline report and a SAMM-aware
  documentation table.
- `self_release` fixture attests DAST as not-applicable (CLI has no
  HTTP surface) so SAMM-VERIF-ST-1 stays fully met under dogfood.

### Fixed

- CLI now forces UTF-8 on `stdout`/`stderr` at startup, so Rich's
  Unicode separators render correctly on Windows consoles without
  requiring `PYTHONIOENCODING=utf-8`. The `sdlc-evidence` console script
  points at the wrapper that applies this, so both `sdlc-evidence` and
  `python -m evidence_collector.cli.main` behave identically.

### Security

- Release artifacts are now signed keyless with cosign; public
  verification recipes live in `SECURITY.md`.
- Dependabot configured for weekly pip / Actions / Docker updates.

## [0.1.0] — 2026-04-23

### Added

- Initial MVP release.
- Canonical Pydantic v2 domain model: `Application`, `ReleaseContext`,
  `EvidenceSource`, `RawEvidenceRef`, `NormalizedEvidence`,
  `ControlDefinition`, `ControlEvaluation`, `Gap`, `Summary`,
  `EvidenceBundle` (schema version `1.0.0`).
- Parsers: SARIF, CycloneDX & SPDX SBOM, JUnit XML, YAML/JSON
  attestations, OWASP ZAP JSON, with a 25 MB safety cap and SHA-256
  integrity hashing per artifact.
- Normalizers that classify SARIF into `sast_scan`, `sca_scan`,
  `secrets_scan` by tool name, and build canonical evidence for SBOM,
  JUnit, ZAP, attestations, PR metadata, and GitHub Actions workflow
  runs.
- Local artifact collector walking `--artifacts-dir`,
  `--attestations-dir`, and `--exceptions-dir` directories.
- GitHub collector over `httpx` for PR approvals (including "last
  approval after last commit" verification) and workflow-run metadata.
- 10-control Secure SDLC catalog mapped to NIST SSDF and org-internal
  IDs, overridable via `--catalog`.
- Control evaluation engine with `met` / `partial` / `missing` /
  `waived` outcomes, explicit rationales, and structured gaps.
- Scoring engine: coverage score, confidence score, release-status
  rules driven by gap criticality.
- Exporters: deterministic `bundle.json`, Jinja2-rendered `report.md`,
  and `summary.html`.
- Typer CLI with `run` / `collect` / `evaluate` / `bundle` /
  `controls` subcommands and `--fail-on` release-gate semantics.
- Time-bound waiver (exception) workflow with scope and expiry.
- Sample release fixture (`examples/sample_release/`) and self-release
  dogfood (`examples/self_release/`).
- Test suite (unit + integration) and GitHub Actions CI pipeline.
