# Maturity Status

Live snapshot of progress against [`MATURITY_ROADMAP.md`](./MATURITY_ROADMAP.md).

> **How to read this file.** Every roadmap item has one row. The `Status`
> column is the source of truth — when an item ships, its row moves to
> `done` in the same commit that ships the change. When the row moves to
> `in progress`, the engineer working on it puts their initials in the
> `Owner` column so we don't double-up. The `Last touched` column is in
> ISO 8601 (UTC) so a stale row is obvious by inspection.

**Last updated:** 2026-05-10 (post-publication hardening pass: docs
reconciled, coverage gate raised, CLI modularized, harden-runner,
classification confidence, `verify` command, snapshot test).
Previous update: 2026-05-05 (release-readiness for v1.1.0 merged into
`main`; maturity/higiene rodada validated baseline).

**Released versions:** v1.0.0 (2026-04-23) · v1.0.1 (2026-05-04,
maturity polish) · v1.1.0 prepared in code on `main` (commit
`17dede2`); the **first signed public release** is still gated on the
external actions table below — no GitHub Release, no PyPI artifact,
no GHCR image has been published yet.

---

## Headline numbers

| Metric                          | Current | Target | Notes                                                                |
|---------------------------------|---------|--------|----------------------------------------------------------------------|
| Tests passing                   | 227     | —      | unit + integration; +84 from the 2026-05-05 coverage push and post-publication hardening (CLI refactor + classification confidence + `verify` command + snapshot test) |
| Line + branch coverage          | 87.43 % | 85 %   | meets target; floor raised from 70 % to 80 % in `pyproject.toml`; measured on 2026-05-05 maturity rodada and re-validated on 2026-05-10 after the hardening pass |
| `mypy --strict` source files    | 61      | —      | zero issues                                                          |
| `ruff` violations               | 0       | 0      | enforced in CI and pre-commit; scope `src tests scripts`             |
| `actionlint` violations         | 0       | 0      | enforced via `pre-commit` and CI                                     |
| `bandit -r src` issues          | 0       | 0      | 3697 LOC scanned, no Low/Medium/High/Undefined                       |
| `semgrep` (security-audit + secrets) findings | 0 | 0 | 148 rules across 206 files; nosemgrep placement fixed in `parsers/junit.py` |
| Workflows pinned (third-party)  | full SHA except 2 structural exceptions | same | All 26 third-party action references pin a full SHA + version comment, except 2 documented structural exceptions (`slsa-framework/slsa-github-generator/.../v2.0.0` reusable-workflow contract, `pypa/gh-action-pypi-publish@release/v1` Trusted-Publisher pattern). The 6 candidates that previously sat on tag (`attest-build-provenance`, `deploy-pages`, `download-artifact`, `upload-pages-artifact`, `cosign-installer`, `action-gh-release`) were converted to SHA on 2026-05-05. Inventory: `docs/program/actions-pinning-inventory.md`. |
| Release artifacts signed        | configured | yes | cosign keyless + Sigstore Rekor wired in `release.yml`; first signed public release will be `v1.1.0`. No signed asset has been published yet. |
| Determinism gate                | yes     | yes    | structural SHA-256 compare in CI; volatile fields documented         |
| Native CodeQL coverage          | yes     | yes    | `python` and `actions` languages on push, PR, and weekly schedule; SARIF upload blocked while repo is private (see external actions) |
| OpenSSF Scorecard score         | pending | ≥ 7    | workflow shipped; first run requires the repository to be public     |

---

## Tier 1 — High impact, low effort

| ID   | Item                                | Status | Owner | Last touched | Notes                                                                                  |
|------|-------------------------------------|--------|-------|--------------|----------------------------------------------------------------------------------------|
| T1.1 | OpenSSF Scorecard workflow          | done   | LHG   | 2026-05-04   | `.github/workflows/scorecard.yml`; weekly + on push to main; SARIF to Security tab     |
| T1.2 | Native CodeQL workflow              | done   | LHG   | 2026-05-04   | `.github/workflows/codeql.yml`; matrix `python` + `actions`; security-and-quality      |
| T1.3 | `pre-commit` hooks                  | done   | LHG   | 2026-05-04   | adds gitleaks, actionlint, hygiene hooks on top of existing ruff/mypy config           |
| T1.4 | Determinism gate in CI              | done   | LHG   | 2026-05-04   | structural SHA-256 compare; documented "volatile" fields in README and gate            |
| T1.5 | `sdlc-evidence doctor` command      | done   | LHG   | 2026-05-04   | health-check command, `--json` for CI, 6 unit tests, exits 1 on required failure       |

## Tier 2 — High impact, medium effort

| ID   | Item                                                | Status | Owner | Last touched | Notes                                                                                    |
|------|-----------------------------------------------------|--------|-------|--------------|------------------------------------------------------------------------------------------|
| T2.1 | SLSA Build Level 3 provenance                       | done   | LHG   | 2026-05-04   | `slsa-github-generator/generator_generic_slsa3.yml@v2.0.0` next to `attest-build-prov.`  |
| T2.2 | Self-SBOM, signed                                   | done   | LHG   | 2026-05-04   | `cyclonedx-bom` in release.yml; signed with cosign sign-blob; attached to GH Release     |
| T2.3 | Multi-arch Docker image, signed, with SBOM          | done   | LHG   | 2026-05-04   | `publish-container` job: amd64+arm64 to ghcr.io, cosign sign + syft + cosign attest      |
| T2.4 | Mutation testing                                    | done   | LHG   | 2026-05-04   | `.github/workflows/mutation.yml` weekly + dispatch; mutmut config focused on parsers     |
| T2.5 | Structured logs with `--json-logs`                  | done   | LHG   | 2026-05-04   | global flag + `SDLC_JSON_LOGS=1` env var; emits NDJSON; 2 unit tests                     |

## Tier 3 — Product maturity

| ID   | Item                                       | Status | Owner | Last touched | Notes                                                                                     |
|------|--------------------------------------------|--------|-------|--------------|-------------------------------------------------------------------------------------------|
| T3.1 | ADRs in `docs/adr/`                        | done   | LHG   | 2026-05-04   | 5 ADRs covering Pydantic v2, deterministic JSON, Typer, evidence-first, catalog override  |
| T3.2 | Public threat model                        | done   | LHG   | 2026-05-04   | `THREAT_MODEL.md` at repo root: STRIDE-by-component, residual risks, supply-chain section |
| T3.3 | Property-based testing with `hypothesis`   | done   | LHG   | 2026-05-04   | 3 properties on JUnit, SARIF, scoring monotonicity; surfaced `critical` bucket as a real classifier  |
| T3.4 | mkdocs-material site                       | done   | LHG   | 2026-05-04   | `mkdocs.yml`, `docs/index.md`; published at `/docs/` of the GitHub Pages deploy           |
| T3.5 | Python 3.13 in CI matrix                   | done   | LHG   | 2026-05-04   | `github-ci-cd.yml` quality job runs in matrix `[3.12, 3.13]`; classifiers updated         |

## Tier 4 — Scale and community

| ID   | Item                                          | Status  | Owner | Last touched | Notes                                                                                              |
|------|-----------------------------------------------|---------|-------|--------------|----------------------------------------------------------------------------------------------------|
| T4.1 | Plugin system for custom parsers              | done    | LHG   | 2026-05-04   | entry-point groups in pyproject.toml + `evidence_collector.plugins` discovery + `sdlc-evidence plugins` CLI; auto-wiring deferred  |
| T4.2 | Optional FastAPI REST surface                 | done    | LHG   | 2026-05-04   | `[api]` extra; read-only surface (`/healthz`, `/version`, `/schema`, `/catalog`, `/plugins`); 5 unit tests |
| T4.3 | OSCAL exporter                                | done    | LHG   | 2026-05-04   | `sdlc-evidence oscal` command; OSCAL 1.1.x Catalog model; 4 unit tests including UUID stability    |
| T4.4 | Issue labels + stale-bot                      | partial | LHG   | 2026-05-04   | `.github/labels.yml` synced via `labels.yml` workflow; `stale.yml` daily cleanup; **Discussions enable still requires GitHub UI action** |
| T4.5 | Conventional-commit-driven release tooling    | done    | LHG   | 2026-05-04   | release-please workflow + config + manifest seeded at v1.0.1; merging the PR auto-tags and triggers `release.yml` |

---

## External actions still required

These items cannot be completed by editing the repository alone — they
need a one-time configuration step on a third-party platform. Status
checked on 2026-05-05.

| Action                                            | Owner | Done? | Status / how it was checked                                                                        |
|---------------------------------------------------|-------|-------|----------------------------------------------------------------------------------------------------|
| Make the GitHub repository public                 | LHG   | no    | `gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector` returns `"visibility":"private"`. Until this changes, the Security CI/CD upload-sarif jobs (CodeQL/Trivy/Semgrep), Dependency Review, and Scorecard cannot publish results. Documented in `docs/program/_archive/2026-05-05/security-ci-failure-analysis.md`. |
| Create the project on PyPI                        | LHG   | no    | Required before the `publish-pypi` job in `release.yml` can succeed. `pypi.org/pypi/secure-sdlc-evidence-collector/json` returns 404. |
| Add GitHub Trusted Publisher on PyPI              | LHG   | no    | Owner `lucashgrifoni`, repo `Secure-SDLC-Evidence-Collector`, workflow `release.yml`, env `pypi`.  |
| Create the GitHub `pypi` environment              | LHG   | no    | Needed for the OIDC token exchange against PyPI Trusted Publisher.                                  |
| Configure branch protection on `main`             | LHG   | no    | Required for OpenSSF Scorecard "Branch-Protection" check to score above zero. `gh api repos/.../branches/main/protection` returns 404. |
| Enable GitHub Discussions                         | LHG   | no    | Tier 4 prerequisite. `gh repo view` shows `hasDiscussionsEnabled=false`.                            |
| Enable GitHub code scanning + secret scanning     | LHG   | no    | Repo metadata reports `security_and_analysis: null` while repo is private; both turn on automatically once the repo becomes public. |
| Run OpenSSF Scorecard                             | LHG   | no    | Workflow shipped (`scorecard.yml`); needs the repo to be public so the action can read public branch-protection / dependency metadata. |
| Add `SNYK_TOKEN` secret (optional)                | LHG   | no    | Only required if the Snyk jobs in `security-ci-cd.yml` are kept. Without it those jobs fail at the `Authenticate Snyk` step. |

---

## Change log of this document

- **2026-05-04** — initial creation. Captured v1.0.1 baseline numbers,
  marked all five Tier 1 items as `in progress`.
- **2026-05-04** — Tier 1 complete. T1.1-T1.5 shipped in a single
  commit: Scorecard + CodeQL workflows, expanded `pre-commit` config,
  structural-determinism CI gate, and the `sdlc-evidence doctor`
  command with 6 unit tests. Total tests 123 → 129, coverage 77.6 % →
  78.2 %, mypy strict files 52 → 53.
- **2026-05-04** — Tier 2 complete. T2.1 SLSA L3 provenance via
  `slsa-github-generator`; T2.2 collector self-SBOM (CycloneDX) signed
  with cosign and attached to the GitHub Release; T2.3 new
  `publish-container` job that builds multi-arch (amd64+arm64) images,
  pushes to ghcr.io, signs them keyless and attaches a syft-generated
  SBOM as a cosign attestation; T2.4 weekly mutation-testing workflow
  with mutmut; T2.5 `--json-logs` global flag (also `SDLC_JSON_LOGS=1`)
  emitting NDJSON events with 2 unit tests. Tests 129 → 131,
  mypy strict files 53 → 54.
- **2026-05-04** — Tier 3 complete. T3.1 5 ADRs (Pydantic v2,
  deterministic JSON, Typer, evidence-first, catalog override);
  T3.2 public threat model `THREAT_MODEL.md` (STRIDE per component,
  residual risks, supply-chain mitigations); T3.3 hypothesis property
  tests for JUnit attribute fuzzing, SARIF severity classification, and
  scoring monotonicity — surfaced `critical` as a real bucket the
  hand-written tests had missed; T3.4 mkdocs-material site at `/docs/`
  of the Pages deploy alongside the existing evidence summary at `/`;
  T3.5 CI matrix Python 3.12 + 3.13. Tests 131 → 134,
  mypy strict files 54 → 55.
- **2026-05-04** — Tier 4 complete. T4.1 plugin system: entry-point
  groups `evidence_collector.parsers` and `evidence_collector.collectors`
  in pyproject.toml; `evidence_collector.plugins` discovery API;
  `sdlc-evidence plugins` CLI; `docs/plugins.md` contract published;
  auto-wiring into `LocalArtifactCollector` deferred to a follow-up.
  T4.2 optional FastAPI surface under `[api]` extra; read-only
  endpoints (healthz, version, schema, catalog, plugins) with 5 unit
  tests. T4.3 OSCAL Catalog exporter via `sdlc-evidence oscal` (OSCAL
  1.1.x); 4 unit tests including UUID stability across runs. T4.4
  partial: `.github/labels.yml` synced by `labels.yml` workflow,
  `stale.yml` daily cleanup with conservative thresholds; enabling
  GitHub Discussions still needs a UI action. T4.5 release-please
  workflow + config + manifest seeded at v1.0.1 — merging the
  release-please PR will auto-tag and trigger `release.yml`. The
  hypothesis test surfaced a real parser bug (`_parse_float` accepted
  `-inf`/`nan`); fixed by clamping to default. Tests 134 → 143,
  mypy strict files 55 → 61.

**Roadmap status:** all four tiers shipped in code on `main`. The
remaining work is the **External actions** table above; until those
land the project is internally `GO WITH CAVEATS` (sample release
green, all local gates green) and externally `NO-GO` for tagging the
first signed public release.

- **2026-05-05** — release-readiness pass for `v1.1.0` merged into
  `main` (commit `17dede2`): repository identity normalized to
  `lucashgrifoni/Secure-SDLC-Evidence-Collector`, canonical
  Apache-2.0 LICENSE + PEP 639 metadata, version bump 1.0.1→1.1.0,
  CI installs `.[dev,api]` so `mypy --strict` resolves the FastAPI
  surface, scripts/ under ruff, public claims downgraded to
  "configured in `release.yml`" until the first signed release.
  Validated with `python -m build` (no license warning) and the same
  local-gate set documented in
  `docs/release-readiness.md`. Eight Dependabot PRs (#1, #2, #3, #4,
  #6, #7, #8, #9) and the `ossf/scorecard-action` patch (#14) were
  triaged and merged on the same day; six newer Dependabot PRs that
  surfaced during the merge cycle (#11 `mutmut`, #12
  `release-please-action`, #13 `attest-build-provenance`, #15
  `actions/upload-pages-artifact`, #16 `docker/login-action`, #17
  `github/codeql-action`) are tracked under HOLD in
  `docs/program/dependabot-triage.md` because they touch
  release/SLSA/CodeQL surfaces that need the first public release as
  baseline.
- **2026-05-05** — maturity/higiene rodada (this update): re-ran the
  full local gate set including `bandit -r src` (0 findings) and
  `semgrep --config p/security-audit --config p/secrets` (148 rules,
  0 findings) after fixing the placement of the `# nosemgrep`
  suppression in `parsers/junit.py`. Reconciled `MATURITY_STATUS.md`,
  `release-readiness.md` and `traceability.md` with the observed
  state.
