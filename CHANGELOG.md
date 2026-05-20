# Changelog

All notable changes to this project are documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.2](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/compare/v2.0.1...v2.0.2) (2026-05-20)


### Fixed

* **security:** remediate code-scanning findings ([#38](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/issues/38)) ([b93062e](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/commit/b93062e3e0a1d7ad1e9547901b3bd8667a92169f))

## [2.0.1](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/compare/v2.0.0...v2.0.1) (2026-05-20)


### Documentation

* **release:** add v2.0.0 release notes source file ([174ca8b](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/commit/174ca8b0cdba547fe334b48548f18d0451f04272))


### CI

* **release-please:** authenticate with a GitHub App token ([#32](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/issues/32)) ([c010845](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/commit/c010845e8da1e1f9d0257a2e23f8f0d2b443bb83))
* standardize and harden GitHub Actions workflows ([#30](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/issues/30)) ([86e635e](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/commit/86e635e0d956f998b36b1db876b741eff13cd466))

## [Unreleased]

## [2.0.0] - 2026-05-19

> Tier 6 cut. First public release of the project. The whole change set is
> additive against the v1.x evidence schema: pipelines that produced
> v1.2.x bundles can move to 2.0 without changing their artifacts and
> see the new fields appear as opt-in extras.

### Added

#### Standards alignment (Sprint 1 / Phase A — T6.1, T6.2, T6.3, T6.4)

- **CycloneDX 1.7 (ECMA-424 2nd Ed.) parser.** `parsers/sbom.py`
  reads `metadata.lifecycles[]` into
  `evidence.metadata.lifecycle_phases` and surfaces
  `vulnerabilities[*].analysis` inline VEX through to the OpenVEX
  exporter. Backward-compatible with 1.5 and 1.6.
- **OSV / OSV-Scanner native parser.** New `parsers/osv.py` consumes
  both the OSV-Scanner `results[]` envelope and a single OSV
  vulnerability record. Auto-detected by `LocalArtifactCollector`
  via `_looks_like_osv`. Ecosystem list lands in
  `evidence.metadata.ecosystems`. OSV-Scanner SARIF was already
  classified as `sca_scan` by the SARIF driver token map.
- **in-toto Statement v1 predicate-type variants.**
  `sdlc-evidence statement --predicate-type witness|evidence-bundle|slsa-provenance`
  emits the same in-toto envelope under three different
  `predicateType` URIs. ADR-0007. Round-trip safe through DSSE.
- **SSDF 1.2 opt-in catalog** (`catalog-ssdf-1.2.yaml`). Refines
  PS.3 to require both SBOM and `artifact_attestation`; adds the
  new PW.6 control for build-process hardening. Default catalog
  stays on SSDF 1.1.
- **Reproducible wheel gate (T6.C4).** Promoted from Sprint 5 to
  Sprint 1 so the gate is in place before v2.0 lands.
  `publish-pypi.yml` pins `SOURCE_DATE_EPOCH` from the tag commit and
  rebuilds the wheel a second time, failing the workflow if the
  SHA-256 drifts. sdist is checked as a warning only (gzip-header
  drift is upstream tooling).

#### AI evidence track (Sprint 2 / Phase B — T6.5)

- **Five new evidence types.** `model_card`,
  `prompt_injection_test_result`, `ai_safety_eval`,
  `mcp_tool_inventory`, `ai_training_data_lineage`. Added to
  `EvidenceType` without bumping `schema_version`.
- **Three new `SubjectType` values.** `ai_model`, `ai_agent`,
  `ai_dataset`.
- **Three new parsers.** `parsers/garak.py` (JSON-Lines garak
  report with `init`, `digest`, `attempt` records),
  `parsers/lm_eval.py` (lm-evaluation-harness JSON; model id from
  `model_args.pretrained` → `model` → `model_name`), and
  `parsers/model_card.py` (Hugging Face Hub frontmatter +
  Google Model Card Toolkit).
- **AI catalog** (`catalog-ai.yaml`). Ten controls mapped to
  SP 800-218A practices, OWASP LLM Top 10, and OWASP Agentic
  Top 10. Opt-in via `--catalog`.
- **Auto-detect in `LocalArtifactCollector`.** Filename + content
  sniffing routes `*.garak.json[l]`, `*.lm-eval.json`, and
  `model-card.json` to the right parser.
- **`docs/ai-evidence.md`** explains how to instrument an AI
  release and what the bundle records.
- **ADR-0008** documents the schema-stable, opt-in design and the
  framework crosswalk.

#### Risk-weighted verdict + multi-VEX + reachability (Sprint 3 / Phase C — T6.6, T6.7, §3.2)

- **`--risk-mode epss-weighted`.** Opt-in flag on
  `sdlc-evidence run`. Re-derives `release_status` using the
  EPSS / KEV signal already in the bundle: KEV with
  `known_ransomware` forces NOT_READY, any exploitable CVE
  downgrades to at least CONDITIONAL, otherwise the base verdict
  is preserved. Only downgrades, never upgrades. New
  `Summary.risk_assessment` block records the rationale; absent
  when the mode is off. ADR-0009.
- **Multi-VEX consumer.** `sdlc-evidence vex --consume <file>`
  ingests OpenVEX, CycloneDX VEX, and CSAF, merges them with the
  bundle-derived statements under a `--policy first-wins|last-wins|fail`
  choice. SPDX VEX is intentionally deferred to v2.1 (low industry
  adoption today).
- **Optional `Reachability` field on `NormalizedEvidence`.**
  Records the upstream verdict from CodeQL reachability / Endor
  Labs / Semgrep Pro / manual review. Status canonicalised to
  `reachable | not_reachable | unknown`; method canonicalised to
  `data_flow | function_call | manual_review`. Risk-weighted mode
  honours `not_reachable` (CVE removed from exploitable count);
  `unknown` and `reachable` keep the signal so a missing tool
  cannot silently suppress risk. ADR-0010.
- **Structural-hash stability preserved.** `application/integrity.py`
  strips `risk_assessment: null` and `reachability: null` before
  hashing so pre-T6.6 / pre-§3.2 bundles continue to hash
  identically when the new features are off.

#### Regulatory + graph (Sprint 4 / Phase D — T6.8, T6.9)

- **Regulatory profiles.** `sdlc-evidence run --profile cra-2026`
  annotates each evidence with `metadata.cra.exploitation_status`
  (mapped from KEV / EPSS) and `metadata.cra.disclosure_deadline`
  (24h from release timestamp), and
  `--profile fedramp-20x` stamps `metadata.fedramp.retention_years = 10`.
  ADR-0011.
- **FedRAMP 20x KSI catalog** (`catalog-fedramp-20x-ksi.yaml`).
  Ten controls covering the KSI Low + Moderate baselines the
  collector can satisfy with existing evidence types. Continuous
  monitoring KSIs that require telemetry the collector does not
  ingest are deliberately omitted.
- **GUAC adapter** (`sdlc-evidence guac`). Translates the bundle
  into a `guac-collect` v1.0 container (`exporters/guac.py`) that
  `guacone collect files` ingests in one shot. ADR-0012. The
  watch daemon (continuous webhooks → delta bundles) is deferred
  to v2.1 — documented in `docs/limitations.md §17`.

#### Community + adoption (Sprint 5 / Phase E)

- **Reusable GitHub Actions workflow.**
  `.github/workflows/reusable-evidence-collection.yml` accepts
  application / repo / release-id / catalog / risk-mode / profile
  inputs and uploads the bundle as an artifact. One `uses:` line
  drops the collector into any pipeline.
- **GitLab CI template.**
  `examples/gitlab-ci/secure-sdlc-evidence.yml` exposes a
  `.secure-sdlc-evidence` job class with the same inputs.
- **Devcontainer + Codespaces.**
  `.devcontainer/devcontainer.json` plus a `postCreate.sh` script
  that installs the project, cosign, syft, trivy, and conftest in
  a Python 3.12 base image. `gh codespaces create` is now a
  zero-config onboarding path.
- **`docs/comparison.md`.** Honest crosswalk against Chainguard
  Enforce, Scribe Trust Hub, GUAC, Kusari Trustify, Lineaje,
  OpenSSF Scorecard, and Snyk / Mend / Sonatype. Calls out
  "honesty check" cases where another tool is better for a
  specific job.

#### Public-launch enablement (Sprint 6)

- **`docs/program/PUBLICATION-RUNBOOK.md`.** Seven phases with
  exact `gh` / `git` / `cosign` commands, rollback table, and
  done criteria for the v2.0.0 cut.
- **`docs/program/openssf-bestpractices-answers.md`.** Pre-drafted
  answers for every non-obvious bestpractices.dev question at the
  Passing tier so the self-assessment is a copy-paste exercise
  for the maintainer.

### Changed

- `Summary` gained `risk_assessment: RiskAssessment | None`,
  `NormalizedEvidence` gained `reachability: Reachability | None`,
  and `EvidenceType` / `SubjectType` gained the AI values. All
  additions are additive and default-`None`; consumers that did
  not opt in see the same JSON shape they saw under v1.2.
- `application/integrity.py` now drops `reachability: null` and
  `summary.risk_assessment: null` before hashing, preserving
  byte-stability for pre-v2.0 bundles.
- `cli/commands/run.py` learned `--risk-mode`,
  `--epss-percentile-threshold`, and `--profile` flags.
- `cli/commands/vex.py` learned `--consume` (repeatable) and
  `--policy`.

### Fixed

- `.gitignore` now ignores `.venv-*/` so the
  `.venv-publication-check/` scratch env used by the local
  pre-publication gate stops appearing as untracked.

### Security

- New CycloneDX 1.7 inline VEX consumption respects existing
  waiver precedence: explicit `EvidenceException` always wins
  over any inline analysis (documented in `exporters/vex.py`).
- Multi-VEX merger does NOT validate the consumed file's
  signature — `docs/limitations.md §16` makes that explicit so
  pipelines that need authenticity verify the signature before
  invoking `vex --consume`.
- `Reachability.status == "unknown"` is treated as "could be
  exploitable" by `--risk-mode epss-weighted` so a missing
  reachability tool cannot silently suppress risk.

### Migration notes (v1.2 → v2.0)

- **Schema version unchanged.** No code change is required for
  consumers that already accepted v1.2 bundles.
- **New optional fields appear as `null` when not opted-in.**
  Strict consumers that key off `Summary.risk_assessment` or
  `NormalizedEvidence.reachability` should treat `null` as "the
  feature was not engaged"; the structural hash gate strips the
  nulls so deterministic verification still works.
- **CLI surface is additive.** `--risk-mode`, `--profile`, and
  `vex --consume` / `--policy` are new flags; defaults keep the
  v1.2 behaviour.
- **AI catalog is opt-in.** Pipelines that do not ship AI
  artifacts see no change.

### Sprint 0 / v1.2 preparatory docs (carried over)

- **Governance + contributor ladder (T6.C3).** New `GOVERNANCE.md`
  documenting the BDFL decision model honestly (single maintainer
  today; tie-break rule pre-staged for the next maintainer), new
  `MAINTAINERS.md` with the active roster + security contact + how to
  reach the maintainer, and a "How to become a maintainer" section
  added to `CONTRIBUTING.md`. Prerequisite for the OpenSSF Best
  Practices Badge Silver tier (future) and for the GitHub Secure Open
  Source Fund application narrative.
- **Rego + Kyverno policy snippets (T6.C5).** New
  `policies/rego/release-ready.rego` (with `release-ready_test.rego`
  cases) and `policies/kyverno/require-evidence.yaml`. New CI gate at
  `.github/workflows/policy-tests.yml` runs `conftest test` and
  `kyverno apply --policy` on every push / PR so the snippets stay
  consumable end-to-end. Closes the "what do I do with this JSON"
  question for OPA / Kyverno operators consuming the bundle at
  admission time.
- **MATURITY_STATUS** refreshed with Tier 5 + Tier 6 progress and a
  detailed change-log entry for 2026-05-18 and 2026-05-19.

## [1.2.0] - TBD (first signed public release; pending Blocks A–H in `docs/program/EXTERNAL-ACTIONS-2026-05-18.md`)

### Added

#### 2026-05-18 — Tier 5: evidence enrichment + supply-chain alignment

- **EPSS + CISA KEV enrichment** (`sdlc-evidence enrich`). New
  `evidence_collector.intelligence` package loads the public EPSS feed
  (FIRST.org, CSV or .csv.gz) and the CISA KEV catalog and attaches a
  compact `vulnerability_intelligence` summary to every evidence record
  that carries CVE ids. Air-gap friendly: no network in the CLI; users
  point at local feed files. SARIF and CycloneDX parsers now extract
  CVE ids into a new `evidence[*].cve_ids` field.
- **OpenVEX 0.2.0 export** (`sdlc-evidence vex`). Emits one OpenVEX
  statement per CVE, mapping bundle exceptions to `not_affected` with
  justification, KEV-listed CVEs to `affected` with action statement,
  and the rest to `under_investigation`. Document `@id` is a UUIDv5
  over (application, repository, release_id, commit_sha) so the file
  is deterministic across runs.
- **OSCAL Assessment Results export** (`sdlc-evidence oscal --kind
  assessment-results`). Renders the bundle's `ControlEvaluation` list
  as an OSCAL 1.1.2 `assessment-results` document — the FedRAMP 20x
  machine-readable shape. UUIDs are stable UUIDv5 across runs.
- **in-toto Statement v1 wrapper** (`sdlc-evidence statement`).
  Wraps the bundle as an in-toto Statement with a project-specific
  predicateType, deterministic UUIDv5 subject name, and an optional
  unsigned DSSE envelope ready for `cosign sign-blob`. Makes the
  bundle natively consumable by Sigstore, GUAC, Kyverno, and OPA
  Gatekeeper without bespoke envelope code.

### Fixed

#### 2026-05-17 — cross-OS structural-SHA stability

- **`normalize_bundle` now POSIX-normalizes `evidence[*].raw.artifact_path`
  before hashing.** Previously the helper trusted whatever separator the
  host had baked into the bundle, so Windows runs produced a different
  structural SHA-256 than Linux runs for the same inputs. The fix
  changes only the hash-time view; the bundle written to disk still
  records native separators. New unit tests
  (`tests/unit/test_integrity.py`) lock the cross-OS behaviour directly,
  and the `test_sample_release_bundle_sha256_snapshot` integration test
  now passes `artifact_root=repo_root` so paths are recorded relative to
  the repo (not absolute, which would still be runner-specific).
- **Snapshot fixture bumped**
  (`tests/fixtures/sample_release_snapshot.sha256`) from
  `34f3025e3791…` to `a42920b3b7b5…` (cross-OS fix on 2026-05-17),
  then to `5e1498cdfdca…` on 2026-05-18 because the
  `mixed-line-ending` pre-commit hook renormalized four sample-release
  input fixtures from CRLF to LF, changing their SHA-256 (which is
  carried into `bundle.json` as `evidence[*].raw.integrity_hash`).
  The current digest is identical on Windows and Linux.

### Added

#### 2026-05-10 — post-publication hardening pass

- **`sdlc-evidence verify` command.** Re-normalizes a `bundle.json`
  and recomputes the structural SHA-256 to validate bundle integrity
  on the consumer side, returning exit code 0 on match and 2 on
  drift. Complements `compare` (semantic diff) with a deterministic
  integrity gate suitable for download-and-verify flows.
- **`classification.confidence` field on each `Evidence`.** Promotes
  the implicit confidence signal in `evidence[*].rationale` (high
  when the SARIF driver name matches the known classification map,
  low when it falls back to `sast_scan`) to a first-class bundle
  field so downstream consumers can filter or weight evidence by
  confidence without parsing free-text rationale.
- **Deterministic bundle snapshot test**
  (`tests/integration/test_bundle_snapshot.py`). Locks the structural
  SHA-256 of the canonical `examples/sample_release` bundle into a
  versioned fixture; any change to parsers, normalizers, scoring or
  the canonical JSON encoder breaks the snapshot explicitly and
  forces an intentional snapshot update.
- **`step-security/harden-runner` on every workflow job.** All
  `.github/workflows/*.yml` jobs start by enabling
  `step-security/harden-runner` in `audit` mode, so runner egress is
  recorded and a future `block` policy is one diff away.
- **ADR-0006 — CLI command modularization** documenting the split of
  `cli/main.py` into `cli/commands/*.py` with the `register(app)`
  pattern.

#### 2026-05-05 — maturity/higiene rodada

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
  (`docs/program/release-runbook.md`) and
  **post-release verification script**
  (`scripts/verify-release.sh`) automating cosign verify-blob,
  slsa-verifier, GHCR verify, attestation download and PyPI
  fresh-venv smoke.
- **Tier 4 surface coverage in `THREAT_MODEL.md`**: new STRIDE rows
  for the FastAPI read-only API, plugin entry-point system and
  OSCAL exporter (Section 2.5).

### Changed

#### 2026-05-10 — post-publication hardening pass

- **CLI split.** `cli/main.py` (811 LOC, 11 commands and helpers in
  one file) was split into `cli/commands/{run, collect, evaluate,
  bundle, controls, compare, oscal, plugins, schema, doctor,
  exceptions, verify}.py` and shared helpers moved to `cli/_render.py`,
  `cli/_logging.py`, `cli/_exit_codes.py`. The `sdlc-evidence`
  entrypoint, flag names, exit codes, output streams and event names
  are unchanged. Verified by the existing `test_cli.py` and
  `test_cli_more_commands.py` suites.
- **Coverage gate raised from `--cov-fail-under=70` to `80`.** The
  project has been operating at ~86 % since the 2026-05-05 maturity
  pass; the previous floor only protected against a 16-point
  regression and did not encode the actual quality bar.
- **`melhorias/` reorganized into `docs/program/`.** The 13-document
  scratch pad from the publication push was consolidated into four
  governance artefacts (publication runbook, dependabot triage log,
  pinning inventory, validation cross-check) and the planning
  prompts/cross-validation scratch were dropped. A pointer file
  `melhorias/README.md` now redirects to the new location to avoid
  breaking external links.
- **Reconciled headline numbers.** README badges (`tests-227`,
  `coverage-87%`), `docs/MATURITY_STATUS.md` headline table and
  `docs/release-readiness.md` "Last local validation pass" all carry
  the same baseline: 227 tests, 87.43 % line + branch coverage.

#### 2026-05-05 — maturity/higiene rodada

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
  pattern). Inventory: `docs/program/actions-pinning-inventory.md`.
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

#### 2026-05-10 — post-publication hardening pass

- **`docs/adr/0006-cli-command-modularization.md`** added documenting
  the why, the trade-offs (more files in exchange for module-level
  testability and review locality) and the migration of helpers.
- Reconciled README badges (`tests-227`, `coverage-87%`),
  `docs/MATURITY_STATUS.md` headline numbers and
  `docs/release-readiness.md` "Last local validation pass" to a
  single source of truth: 227 tests, 87.43 % line + branch coverage.

#### 2026-05-05 — maturity/higiene rodada

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
- **Tier 2 — supply-chain hardening configured in `publish-pypi.yml`.** SLSA
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
  publish-pypi.yml Trusted Publisher comment now all point to
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
  `docs/program/` planning dossier (formerly `melhorias/`).

### Pending external actions for publication (tracked outside this changelog)

- Make repository public; enable Discussions, branch protection on
  `main`, code scanning, and secret scanning.
- Create `secure-sdlc-evidence-collector` on PyPI and configure the
  Trusted Publisher (owner `lucashgrifoni`, repo
  `Secure-SDLC-Evidence-Collector`, workflow `publish-pypi.yml`,
  environment `pypi`).
- Create the GitHub `pypi` environment.
- Until those are done, `publish-pypi.yml` will run quality, build and
  release-bundle but the `publish-pypi` and `publish-container` jobs
  will short-circuit on missing prerequisites. No claim of "published
  on PyPI" or "image signed in GHCR" can be made yet.

## [1.0.1] — 2026-05-04

Maturity polish on top of 1.0.0. No behavioural changes to the bundle
schema, CLI surface, or GitHub Action contract.

### Added

- **PyPI publishing job** in `publish-pypi.yml` using OIDC trusted publisher
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
- **Release workflow** (`.github/workflows/publish-pypi.yml`) that runs all
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
