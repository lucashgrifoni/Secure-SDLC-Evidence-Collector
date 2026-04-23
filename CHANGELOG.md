# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-04-23

### Added

- Initial MVP release.
- Canonical Pydantic v2 domain model: `Application`, `ReleaseContext`,
  `EvidenceSource`, `RawEvidenceRef`, `NormalizedEvidence`,
  `ControlDefinition`, `ControlEvaluation`, `Gap`, `Summary`,
  `EvidenceBundle` (schema version `1.0.0`).
- Parsers: SARIF, CycloneDX & SPDX SBOM, JUnit XML, YAML/JSON attestations
  with a 25 MB safety cap and SHA-256 integrity hashing per artifact.
- Normalizers that classify SARIF into `sast_scan`, `sca_scan`,
  `secrets_scan` by tool name, and build canonical evidence for SBOM,
  JUnit, attestations, PR metadata, and GitHub Actions workflow runs.
- Local artifact collector walking `--artifacts-dir` and
  `--attestations-dir` directories.
- GitHub collector over `httpx` for PR approvals (including "last approval
  after last commit" verification) and workflow-run metadata.
- 10-control Secure SDLC catalog mapped to NIST SSDF practices and
  org-internal IDs; overridable via `--catalog`.
- Control evaluation engine with `met`/`partial`/`missing`/`waived`
  outcomes, explicit rationales, and structured gaps.
- Scoring engine: coverage score, confidence score, release-status rules
  driven by gap criticality.
- Exporters: deterministic `bundle.json`, Jinja2-rendered `report.md`,
  and `summary.html`.
- Typer CLI with `run`, `collect`, `evaluate`, `bundle`, `controls`
  subcommands and `--fail-on` release-gate semantics.
- Sample release fixture (`examples/sample_release/`) demonstrating the
  happy path end-to-end.
- Test suite (unit + integration) with 45 tests and 70% coverage gate.
- GitHub Actions CI pipeline running ruff, ruff format check, mypy strict,
  pytest, and a sample-bundle job that uploads the generated artifacts.
