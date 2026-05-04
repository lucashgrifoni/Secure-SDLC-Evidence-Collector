# Maturity Status

Live snapshot of progress against [`MATURITY_ROADMAP.md`](./MATURITY_ROADMAP.md).

> **How to read this file.** Every roadmap item has one row. The `Status`
> column is the source of truth — when an item ships, its row moves to
> `done` in the same commit that ships the change. When the row moves to
> `in progress`, the engineer working on it puts their initials in the
> `Owner` column so we don't double-up. The `Last touched` column is in
> ISO 8601 (UTC) so a stale row is obvious by inspection.

**Last updated:** 2026-05-04 (Tier 1 shipped)

**Released versions:** v1.0.0 (2026-04-23) · v1.0.1 (2026-05-04, maturity polish)

---

## Headline numbers

| Metric                          | Current | Target | Notes                                                                |
|---------------------------------|---------|--------|----------------------------------------------------------------------|
| Tests passing                   | 129     | —      | unit + integration (+6 from Tier 1 doctor coverage)                  |
| Line + branch coverage          | 78.2 %  | 85 %   | floor enforced at 70 %                                               |
| `mypy --strict` source files    | 53      | —      | zero issues                                                          |
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

| ID   | Item                                                | Status  | Owner | Last touched | Notes |
|------|-----------------------------------------------------|---------|-------|--------------|-------|
| T2.1 | SLSA Build Level 3 provenance                       | pending | —     | —            |       |
| T2.2 | Self-SBOM, signed                                   | pending | —     | —            |       |
| T2.3 | Multi-arch Docker image, signed, with SBOM          | pending | —     | —            |       |
| T2.4 | Mutation testing                                    | pending | —     | —            |       |
| T2.5 | Structured logs with `--json-logs`                  | pending | —     | —            |       |

## Tier 3 — Product maturity

| ID   | Item                                       | Status  | Owner | Last touched | Notes |
|------|--------------------------------------------|---------|-------|--------------|-------|
| T3.1 | ADRs in `docs/adr/`                        | pending | —     | —            |       |
| T3.2 | Public threat model                        | pending | —     | —            |       |
| T3.3 | Property-based testing with `hypothesis`   | pending | —     | —            |       |
| T3.4 | mkdocs-material site                       | pending | —     | —            |       |
| T3.5 | Python 3.13 in CI matrix                   | pending | —     | —            |       |

## Tier 4 — Scale and community

| ID   | Item                                          | Status  | Owner | Last touched | Notes |
|------|-----------------------------------------------|---------|-------|--------------|-------|
| T4.1 | Plugin system for custom parsers              | pending | —     | —            |       |
| T4.2 | Optional FastAPI REST surface                 | pending | —     | —            |       |
| T4.3 | OSCAL exporter                                | pending | —     | —            |       |
| T4.4 | GitHub Discussions + labels + stale-bot       | pending | —     | —            |       |
| T4.5 | Conventional-commit-driven release tooling    | pending | —     | —            |       |

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
