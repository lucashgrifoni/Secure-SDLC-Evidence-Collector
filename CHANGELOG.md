# Changelog

All notable changes to this project are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Cross-OS determinism gate.** `github-ci-cd.yml` now produces the
  sample bundle on a `windows-latest` runner in addition to
  `ubuntu-latest`, and a new `cross-os-determinism` job re-validates
  the normalize-then-SHA-256 invariant across both. The promise in
  `docs/limitations.md §8` ("Linux and Windows should produce the
  same bundle") is now machine-checked instead of human-checked.
- **SARIF classification calibration suite**
  (`tests/unit/test_classification_calibration.py`, 25 tests) that
  locks down the documented FP/FN behaviour from
  `docs/limitations.md §2`.
- **Behaviour test coverage on the four lowest-coverage modules**:
  `test_compare.py` (11 tests), `test_gitlab_collector.py` (15
  tests), `test_jinja.py` (7 tests), `test_cli_more_commands.py`
  (10 tests). Total coverage 77.39 % → **86.38 %** (above the 85 %
  maturity target); test count 143 → **211**.
- **`examples/sample_release/exceptions/`** fixture demonstrating
  `sdlc-evidence exceptions validate / list` against a real
  schema-valid waiver, scoped to a different release context so the
  canonical sample bundle stays `ready 13/13`.
- **Pre-release runbook**
  (`melhorias/runbook-publicacao-v1-1-0-2026-05-05.md`) and
  **post-release verification script**
  (`scripts/verify-release.sh`) automating cosign verify-blob,
  slsa-verifier, GHCR verify, attestation download and PyPI
  fresh-venv smoke.
- **Tier 4 surface coverage in `THREAT_MODEL.md`**: new STRIDE rows
  for the FastAPI read-only API, plugin entry-point system and
  OSCAL exporter (Section 2.5).

### Changed

- **`parsers/junit.py`**: moved the `# nosemgrep:
  python.lang.security.use-defused-xml.use-defused-xml` suppression
  to the line where the `from xml.etree.ElementTree import (...)`
  statement actually starts so Semgrep stops reporting the two
  type-only / exception-only stdlib imports. The actual XML
  parsing remains delegated to `defusedxml`; this is a comment
  placement fix, not a behaviour change. Verified clean with
  `semgrep scan --config p/security-audit --config p/secrets` (148
  rules, 0 findings).
- **All third-party action `uses:` are now SHA-pinned with version
  comment.** The 6 actions previously on tag pin
  (`actions/attest-build-provenance@v1`, `actions/deploy-pages@v4`,
  `actions/download-artifact@v4`, `actions/upload-pages-artifact`
  bumped from v4 to v5 and SHA-pinned in the same diff,
  `sigstore/cosign-installer@v3`, `softprops/action-gh-release@v2`)
  were converted using SHAs resolved via
  `gh api repos/<owner>/<repo>/commits/<tag>`. Two structural
  exceptions remain documented:
  `slsa-framework/slsa-github-generator/.../v2.0.0` (reusable
  workflow contract requires tag pin) and
  `pypa/gh-action-pypi-publish@release/v1` (Trusted-Publisher
  pattern). Inventory: `melhorias/pinning-actions-2026-05-05.md`.
- **`THREAT_MODEL.md` 2.6 supply-chain row** corrected to acknowledge
  the two structural pin exceptions, with pointer to the dossier.
- **Dependabot HOLD list resolved**: 2 PRs merged
  (`actions/upload-pages-artifact@v5`, `docker/login-action@v4`),
  4 closed via `@dependabot ignore this major version` with
  rationale (mutmut 3 dropped Windows native support; release-please
  v5 / attest-build-provenance v4 / codeql-action v4 are major
  bumps deferred until the first signed public release establishes
  a baseline).
- **README "Roadmap > Planned" renamed to "Considered for future
  versions"** with explicit "open ideas, not commitments" framing.

### Documentation

- Refreshed `docs/release-readiness.md` "Last local validation pass"
  to record the 2026-05-05 maturity rodada: ruff/format/mypy/pytest
  green, actionlint clean, gitleaks/pip-audit/Trivy clean, **bandit
  clean (0 issues across 3697 LOC)**, **semgrep clean (148 rules)**,
  sample release `ready` 13/13, sample without attestations
  `not_ready` with the four expected missing critical controls and
  exit code 2 by design. Docker daemon not active in this pass —
  remains a release-time dependency.
- Refreshed `docs/traceability.md` to "Last refreshed: 2026-05-05"
  and added a "Refresh notes — 2026-05-05" section documenting
  exactly which scenarios were re-driven this round (sample positive
  ready 13/13, sample negative not_ready 6 missing exit code 2,
  `compare` 0 deltas, `oscal` and `schema` exports, **all 7
  `examples/labs/*` re-evaluated against committed artifacts with
  the same `not_ready` outcomes documented in §3-§4**, fresh
  `pip install -e .` smoke run in a clean venv) and which were
  inherited (live SCM with token, Docker build).
- Reconciled `docs/MATURITY_STATUS.md` headline numbers with the
  observed baseline: coverage `77.5 %` → **`86.38 %`** (above the
  85 % target), added bandit / semgrep rows, set the SHA-pinning
  row to "full SHA except 2 documented structural exceptions",
  rewrote the "External actions still required" table with honest
  2026-05-05 status (repo private, PyPI absent, no branch
  protection, no Discussions, GHAS off, Scorecard not yet run),
  added 2026-05-05 change-log entries.

## [1.1.0] — 2026-05-05

First release that carries the Tier 1–4 maturity work that landed on
`main` after `v1.0.1` (commits `040a153`, `a537074`, `4a59c74`, `1f84619`).
The bundle schema, CLI flags, GitHub Action input/output contract, and
environment variables remain backwards-compatible with `1.0.x`.

### Added

- **Tier 1 — externally visible quality signals.** OpenSSF Scorecard and
  native CodeQL workflows; expanded `pre-commit` config covering Gitleaks,
  actionlint and hygiene hooks; structural-determinism gate that re-runs
  the sample pipeline and compares normalized SHA-256; `sdlc-evidence
  doctor` health check command (`--json` output for CI).
- **Tier 2 — supply-chain hardening configured in `release.yml`.** SLSA
  Build Level 3 provenance via `slsa-github-generator`; collector
  self-SBOM (CycloneDX) signed with cosign; multi-arch container
  (amd64 + arm64) pushed to `ghcr.io`, signed keyless with cosign and
  attested with a syft-generated SBOM; weekly mutation testing workflow
  with `mutmut`; global `--json-logs` flag (also `SDLC_JSON_LOGS=1`)
  emitting NDJSON.
- **Tier 3 — product maturity.** Five ADRs under `docs/adr/` covering
  Pydantic v2, deterministic JSON, Typer, evidence-first design, and
  catalog override; public `THREAT_MODEL.md` (STRIDE per component,
  residual risks, supply-chain section); Hypothesis property tests for
  JUnit attribute fuzzing, SARIF severity classification and scoring
  monotonicity; `mkdocs-material` technical site published at `/docs/`
  of the GitHub Pages deploy; CI matrix Python 3.12 and 3.13.
- **Tier 4 — scale and community.** Plugin entry-point groups
  (`evidence_collector.parsers`, `evidence_collector.collectors`) with
  discovery API and `sdlc-evidence plugins` CLI; optional FastAPI
  read-only surface under the `[api]` extra (`/healthz`, `/version`,
  `/schema`, `/catalog`, `/plugins`); `sdlc-evidence oscal` exporter
  rendering the catalog as an OSCAL 1.1.x Catalog document; issue
  labels synced via `labels.yml` workflow and daily stale cleanup;
  `release-please` workflow seeded for conventional-commit releases.

### Changed

- **Repository identity.** Homepage, Issues, Source, Docker image
  source, GitHub Action install fallback, CONTRIBUTING clone URL,
  CODEOWNERS, Dependabot reviewers, Issue Template links and the
  release.yml Trusted Publisher comment now all point to
  `lucashgrifoni/Secure-SDLC-Evidence-Collector` (the actual remote)
  instead of the legacy mixed-case `LucasGrifoni/secure-sdlc-evidence-collector`.
- **Modern license metadata in `pyproject.toml`.** Replaced the
  deprecated `license = { text = "Apache-2.0" }` table and the
  `License :: OSI Approved :: Apache Software License` classifier with
  a SPDX `license = "Apache-2.0"` expression and a `license-files =
  ["LICENSE"]` entry. `LICENSE` itself is now the canonical full
  Apache-2.0 text so GitHub detects the license as Apache-2.0 instead
  of `Other`.
- **CI lint scope.** `github-ci-cd.yml` and the Makefile `lint` /
  `format` targets now include `scripts/` so helper scripts stay under
  the same Ruff quality gate as `src/` and `tests/`.
- **README badges and roadmap.** Tests/coverage badges updated to
  reflect the current local baseline (143 tests, 77.39% coverage).
- **Documentation honesty.** README, `docs/index.md`,
  `docs/release-readiness.md`, `docs/MATURITY_STATUS.md` and
  `CHANGELOG.md` now distinguish *configured* (workflow exists),
  *locally validated* (gate ran), *remotely validated* (CI run linked)
  and *published / verified* (release asset and signature). Cosign /
  SLSA / PyPI / GHCR claims are downgraded to "configured" until the
  first signed `v1.1.0` release exists.
- **`docs/release-readiness.md`** points to the stricter
  [public repository readiness gate](./docs/publication-readiness.md),
  targeted at 2026-06-05.
- **`mkdocs.yml` nav** now includes `docs/publication-readiness.md`
  and `docs/plugins.md` (previously off the nav).
- **Self-release dogfood bundle** regenerated against the corrected
  `lucashgrifoni/Secure-SDLC-Evidence-Collector` repository name.

### Fixed

- **Dockerfile `HEALTHCHECK`.** Lightweight liveness probe runs
  `sdlc-evidence --version`.
- **`scripts/scrub_lab_artifacts.py`** reformatted to satisfy
  `ruff format --check` once `scripts/` joined the lint targets.

### Removed

- `Plano de acao e execucao - Claude.md` — legacy execution-handoff
  document. Its content is captured by `docs/release-readiness.md`,
  `docs/MATURITY_ROADMAP.md`, `docs/MATURITY_STATUS.md` and the
  `melhorias/` planning dossier.

### Pending external actions for publication (tracked outside this changelog)

- Make repository public; enable Discussions, branch protection on
  `main`, code scanning, and secret scanning.
- Create `secure-sdlc-evidence-collector` on PyPI and configure the
  Trusted Publisher (owner `lucashgrifoni`, repo
  `Secure-SDLC-Evidence-Collector`, workflow `release.yml`,
  environment `pypi`).
- Create the GitHub `pypi` environment.
- Until those are done, `release.yml` will run quality, build and
  release-bundle but the `publish-pypi` and `publish-container` jobs
  will short-circuit on missing prerequisites. No claim of "published
  on PyPI" or "image signed in GHCR" can be made yet.

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
