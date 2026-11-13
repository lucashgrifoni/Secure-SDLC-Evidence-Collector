# OSPS Baseline self-assessment

This page assesses **this project** against the
[Open Source Project Security Baseline](https://baseline.openssf.org/)
(OSPS Baseline) **v2026.08.28**, the release published on 2026-08-28. It is
unrelated to the `catalog-osps-baseline.yaml` catalog the collector ships:
that catalog evaluates a release's evidence, while this page looks at how the
project itself is run.

- **Assessed:** 2026-11-09, against `main` at `4c9f82f` (release 4.2.0).
  The workflows and branch protection were read again on 2026-11-13, against
  `main` at `171b1e5`.
- **Method:** the repository files named in each row, the 4.2.0 release
  assets, and the repository's GitHub settings read through the GitHub REST
  API (branch protection, collaborators, security features, Actions
  permissions).
- **Status:** a self-assessment by the maintainer, not a certification. The
  project's [OpenSSF Best Practices entry](https://www.bestpractices.dev/projects/15519)
  has the passing badge; its Baseline levels had not been filled in there as
  of 2026-11-09. Entering this assessment on that site is a separate step
  for the maintainer.

Status values: **Met**, **Partial** (part of the requirement is in place;
the gap is named), **Not met**, and **Not verified** (this assessment could
not check it).

## Summary

| Level | Requirements | Met | Partial | Not met | Not verified |
|---|---|---|---|---|---|
| 1 | 24 | 21 | 2 | 0 | 1 |
| 2 | 19 | 17 | 1 | 1 | 0 |
| 3 | 21 | 10 | 7 | 3 | 1 |

OSPS-BR-01.02 is retired in v2026.08.28 and not counted. A requirement
first applies at the level shown and stays required at the levels above it.

## Codebases

The project has one source repository,
[lucashgrifoni/Secure-SDLC-Evidence-Collector](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector).
The GitLab CI/CD Catalog component is published from its
`examples/gitlab-component/` directory to the GitLab project
`lucas.henriquegrifoni/secure-sdlc-evidence-component`, which is a
publication copy, not a separate codebase.

## Level 1

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| OSPS-AC-01.01 | MFA for sensitive repository actions | Not verified | The repository belongs to a personal account. Its two-factor setting is not readable through the repository API, so the owner has to confirm it. |
| OSPS-AC-02.01 | New collaborators get least privilege by default | Partial | On a repository owned by a personal account, GitHub gives every collaborator write access, so there is no lower default to choose. The owner is the only collaborator (admin). |
| OSPS-AC-03.01 | Direct commits to the primary branch are prevented | Partial | Branch protection on `main` requires 15 status checks, applies to administrators and requires conversation resolution. It does not require a pull request, so it does not by itself stop every direct commit. |
| OSPS-AC-03.02 | Deleting the primary branch needs explicit confirmation | Met | Branch protection on `main` disallows deletion and force pushes. |
| OSPS-BR-01.01 | Untrusted CI metadata is sanitized | Met | No workflow uses `pull_request_target` or `workflow_run`, and pull request titles, bodies and branch names never reach a `run:` script. The `workflow_dispatch` tag input of `publish-pypi.yml` passes through an environment variable and an anchored version pattern. One script (`deploy-github-pages.yml`) still expands `github.ref_name` inline; it runs only on pushes to `main` and on manual dispatch. |
| OSPS-BR-01.03 | Untrusted code snapshots get no privileged credentials | Met | Pull requests run on `pull_request`, so fork code gets no secrets. The default `GITHUB_TOKEN` permission is read-only and every workflow declares a read-only top-level `permissions` block. |
| OSPS-BR-03.01 | Official project channels use encrypted transport | Met | The repository, the documentation site, PyPI and GHCR are served over HTTPS. |
| OSPS-BR-03.02 | Distribution channels are authenticated | Met | GitHub Releases, PyPI and GHCR are HTTPS endpoints; release files and the container image are signed with cosign keyless ([verifying signatures](index.md#verifying-signatures)). |
| OSPS-BR-07.01 | Secrets are kept out of version control | Met | GitHub secret scanning and push protection are enabled. "Secrets History - Gitleaks" and "Secrets - Trivy" are required checks on `main`. |
| OSPS-DO-01.01 | User guides for basic functionality | Met | [README](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector#readme) and this documentation site. |
| OSPS-DO-02.01 | Guide for reporting defects | Met | The bug report issue form, and [Discussion #187](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/discussions/187) on how to ask, report a bug or report a security issue. |
| OSPS-GV-02.01 | Public discussion mechanism | Met | Issues and Discussions are enabled. |
| OSPS-GV-03.01 | Contribution process explained | Met | `CONTRIBUTING.md`. |
| OSPS-LE-02.01 | Source license is OSI-approved | Met | `Apache-2.0 AND BSD-2-Clause` (`pyproject.toml`, `LICENSE`, `THIRD_PARTY_LICENSES.md`). |
| OSPS-LE-02.02 | Released assets carry an OSI-approved license | Met | The 4.2.0 wheel metadata declares `License-Expression: Apache-2.0 AND BSD-2-Clause`. |
| OSPS-LE-03.01 | License kept in a LICENSE file in the repository | Met | `LICENSE` and `THIRD_PARTY_LICENSES.md` at the repository root. |
| OSPS-LE-03.02 | License included with released assets | Met | The 4.2.0 wheel ships both files under `dist-info/licenses/`. |
| OSPS-QA-01.01 | Source repository publicly readable at a static URL | Met | The GitHub repository is public. |
| OSPS-QA-01.02 | Public record of changes, authors and dates | Met | Git history on GitHub. |
| OSPS-QA-02.01 | Dependency list for direct dependencies | Met | `pyproject.toml`, plus the hash-locked files in `.github/requirements/`. |
| OSPS-QA-04.01 | List of the project's codebases | Met | [Codebases](#codebases) above. |
| OSPS-QA-05.01 | No generated executable artifacts in version control | Met | No wheels, archives, compiled objects or bytecode among the tracked files. |
| OSPS-QA-05.02 | No unreviewable binary artifacts in version control | Met | No binary files among the tracked files. |
| OSPS-VM-02.01 | Security contacts documented | Met | `SECURITY.md` (private e-mail) and the security contact in `MAINTAINERS.md`. |

## Level 2

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| OSPS-AC-04.01 | CI tasks default to the lowest permissions | Met | The repository's default workflow permission is read-only, and every workflow declares a read-only top-level `permissions` block (`contents: read`, or `read-all` in `scorecard.yml`). |
| OSPS-BR-02.01 | Each release has a unique version identifier | Met | SemVer tags created by release-please. |
| OSPS-BR-04.01 | Release contains a log of functional and security changes | Met | `CHANGELOG.md` and the GitHub Release notes. |
| OSPS-BR-05.01 | Standard tooling ingests dependencies | Met | pip installs from `uv pip compile` lock files with `--require-hashes`; Dependabot proposes updates. |
| OSPS-BR-06.01 | Releases are signed or listed in a signed manifest | Met | The wheel, sdist, release bundle and SBOM are signed with cosign keyless and listed in `checksums.txt`. `3.0.0` has no assets: its pipeline failed before anything was signed. |
| OSPS-DO-06.01 | Documentation says how dependencies are selected, obtained and tracked | Partial | The mechanisms exist (version ranges in `pyproject.toml`, commented `.in` files and hash locks in `.github/requirements/`, Dependabot), but no user-facing page describes them. |
| OSPS-DO-07.01 | Build instructions | Met | README "Install" and "Development" sections and `CONTRIBUTING.md`. |
| OSPS-GV-01.01 | Members with access to sensitive resources are listed | Met | `MAINTAINERS.md`; the GitHub collaborators list holds only the owner. |
| OSPS-GV-01.02 | Roles and responsibilities described | Met | `GOVERNANCE.md`, `MAINTAINERS.md` and the contributor ladder in `CONTRIBUTING.md`. |
| OSPS-GV-03.02 | Contributor guide with acceptance requirements | Met | `CONTRIBUTING.md`: local quality gates and the pull request checklist. |
| OSPS-LE-01.01 | Contributors assert legal authorization on every commit | Not met | No DCO sign-off or CLA is required. |
| OSPS-QA-03.01 | Status checks pass before commits reach the primary branch | Met | 15 required status checks on `main`, enforced for administrators. |
| OSPS-QA-06.01 | CI runs an automated test suite before a change is accepted | Met | "Lint, type-check, and test" on Python 3.12 and 3.13 are required checks. |
| OSPS-SA-01.01 | Design documentation of actions and actors | Met | `THREAT_MODEL.md` (system overview, trust boundaries, adversaries) and the README architecture section. |
| OSPS-SA-02.01 | External software interfaces described | Met | README CLI reference, [bundle schema](bundle_schema.md), [JSON logs events](json-logs.md), [GitHub Action](github_action.md), and the read-only API in [limitations §18](limitations.md). |
| OSPS-SA-03.01 | Security assessment performed | Met | `THREAT_MODEL.md`, STRIDE by component. |
| OSPS-VM-01.01 | Coordinated disclosure policy with a response timeframe | Met | `SECURITY.md`: acknowledgement within 3 business days, remediation plan within 10, disclosure no later than 90 days after the report. |
| OSPS-VM-03.01 | Private vulnerability reporting to the security contacts | Met | Private e-mail in `SECURITY.md`. GitHub private vulnerability reporting is not enabled. |
| OSPS-VM-04.01 | Data about discovered vulnerabilities is published | Met | `SECURITY.md` commits to a patched release, a CVE when applicable and credit in the release notes. No repository security advisory had been published as of 2026-11-09. |

## Level 3

| ID | Requirement (short) | Status | Evidence |
|---|---|---|---|
| OSPS-AC-04.02 | Each CI job gets only the privileges it needs | Met | Jobs grant their own write scopes on top of a read-only default, and each scope is used by a step of that job: `attestations: write` only in jobs that call GitHub's attestation actions, `packages: write` only in the container image job, `security-events: write` only in jobs that upload SARIF. |
| OSPS-BR-01.04 | Trusted collaborator input is sanitized in CI | Partial | The dispatch tag is validated as above; one script (`deploy-github-pages.yml`) still expands `github.ref_name` inline instead of through an environment variable. |
| OSPS-BR-02.02 | Every release asset is tied to the release identifier | Partial | The wheel and sdist names carry the version. `bundle.json`, `report.md`, `summary.html`, `multiple.intoto.jsonl` and the SBOM do not; they are tied to the version only by the tagged release they are attached to. |
| OSPS-BR-07.02 | Policy for managing the project's secrets | Not met | No written policy for storing, accessing and rotating the project's own secrets. |
| OSPS-DO-03.01 | Instructions to verify release integrity and authenticity | Met | [Verifying signatures](index.md#verifying-signatures). |
| OSPS-DO-03.02 | Instructions to verify the identity of the release author | Met | The same section pins the exact signing identity: `publish-pypi.yml` on the release tag, issued by GitHub Actions OIDC. |
| OSPS-DO-04.01 | Scope and duration of support for each release | Partial | `SECURITY.md` says `4.x` is supported and earlier lines are end of life, but gives no support duration. |
| OSPS-DO-05.01 | Statement of when releases stop getting security updates | Partial | `SECURITY.md` names the end-of-life lines; it does not say when `4.x` will stop receiving updates. |
| OSPS-GV-04.01 | Collaborators are reviewed before escalated permissions | Met | The contributor ladder in `CONTRIBUTING.md` sets the criteria for the triager and maintainer roles. |
| OSPS-QA-02.02 | Released assets ship with an SBOM | Met | The collector's CycloneDX SBOM is a release asset, and the container image carries a signed SBOM attestation. |
| OSPS-QA-04.02 | Subprojects are held to the same requirements | Not verified | The GitLab component project's own settings were not reviewed for this page. |
| OSPS-QA-06.02 | Documentation says when and how tests run | Met | `CONTRIBUTING.md` (local gates) and `github-ci-cd.yml` (every pull request and push to `main`). |
| OSPS-QA-06.03 | Policy that major changes add or update tests | Met | The pull request checklist in `CONTRIBUTING.md` requires tests for the happy path and the main failure paths. |
| OSPS-QA-07.01 | A non-author human approves changes before merge | Not met | The project has one maintainer and branch protection requires no review. Automated review comments are not a human approval. |
| OSPS-SA-03.02 | Threat modeling and attack surface analysis | Met | `THREAT_MODEL.md`: trust boundaries, STRIDE by component, residual risks. |
| OSPS-VM-04.02 | VEX for vulnerabilities that do not affect the project | Not met | The project publishes no VEX document about its own dependencies. |
| OSPS-VM-05.01 | Policy with remediation thresholds for SCA findings and licenses | Partial | CI thresholds exist (`security-ci-cd.yml`: Trivy fails on medium and above, Dependency Review on moderate and above), but no written remediation-time policy, and none for licenses. |
| OSPS-VM-05.02 | SCA violations are addressed before a release | Met | The [release checklist](release-readiness.md) requires Dependabot to be green or every open alert to be waived; "SCA - Trivy" is a required check. |
| OSPS-VM-05.03 | Changes are checked for vulnerable and malicious dependencies and blocked | Partial | "SCA - Trivy" is a required check that fails on known vulnerabilities of medium severity and above. Dependency Review runs on pull requests but is not required, and nothing checks for malicious packages. |
| OSPS-VM-06.01 | Policy with remediation thresholds for SAST findings | Partial | Semgrep fails the build on findings of WARNING severity and above, but no written remediation-time policy exists. |
| OSPS-VM-06.02 | Changes are checked for security weaknesses and blocked | Met | "SAST - Semgrep" (run with `--error`) is a required check. CodeQL is required to run; its alerts go to code scanning without blocking the merge. |

## Keeping this page current

Re-assess when the OSPS Baseline publishes a new release, when branch
protection or the release workflow changes, and at each minor release. The
gaps above are listed as facts; which of them to close, and when, is the
maintainer's decision.
