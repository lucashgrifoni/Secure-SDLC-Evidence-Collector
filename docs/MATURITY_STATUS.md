# Maturity Status

Live snapshot of progress against [`MATURITY_ROADMAP.md`](./MATURITY_ROADMAP.md).

> **How to read this file.** Every roadmap item has one row. The `Status`
> column is the source of truth — when an item ships, its row moves to
> `done` in the same commit that ships the change. When the row moves to
> `in progress`, the engineer working on it puts their initials in the
> `Owner` column so we don't double-up. The `Last touched` column is in
> ISO 8601 (UTC) so a stale row is obvious by inspection.

**Last updated:** 2026-05-04 (Tier 4 shipped — full roadmap done)

**Released versions:** v1.0.0 (2026-04-23) · v1.0.1 (2026-05-04, maturity polish)

---

## Headline numbers

| Metric                          | Current | Target | Notes                                                                |
|---------------------------------|---------|--------|----------------------------------------------------------------------|
| Tests passing                   | 143     | —      | unit + integration (+9 from Tier 4: API + OSCAL exporter)            |
| Line + branch coverage          | 77.5 %  | 85 %   | floor enforced at 70 %                                               |
| `mypy --strict` source files    | 61      | —      | zero issues                                                          |
| `ruff` violations               | 0       | 0      | enforced in CI and pre-commit                                        |
| `actionlint` violations         | 0       | 0      | enforced via `pre-commit` and CI                                     |
| Workflows pinned by SHA         | yes     | yes    | third-party actions                                                  |
| Release artifacts signed        | yes     | yes    | cosign keyless + Sigstore Rekor                                      |
| Determinism gate                | yes     | yes    | structural SHA-256 compare in CI; volatile fields documented         |
| Native CodeQL coverage          | yes     | yes    | `python` and `actions` languages on push, PR, and weekly schedule    |
| OpenSSF Scorecard score         | pending | ≥ 7    | workflow shipped; first run executes after this commit reaches main  |

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
need a one-time configuration step on a third-party platform.

| Action                                            | Owner | Done? | Notes                                                                                              |
|---------------------------------------------------|-------|-------|----------------------------------------------------------------------------------------------------|
| Create the project on PyPI                        | LHG   | no    | Required before the `publish-pypi` job in `release.yml` can succeed.                               |
| Add GitHub Trusted Publisher on PyPI              | LHG   | no    | Owner `lucashgrifoni`, repo `Secure-SDLC-Evidence-Collector`, workflow `release.yml`, env `pypi`.  |
| Enable GitHub Discussions                         | LHG   | no    | Tier 4 prerequisite.                                                                               |
| Configure branch protection on `main`             | LHG   | no    | Required for OpenSSF Scorecard "Branch-Protection" check to score above zero.                      |

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

**Roadmap status:** all four tiers shipped. The single remaining
non-engineering action is enabling GitHub Discussions in repo settings
(documented under "External actions still required").
