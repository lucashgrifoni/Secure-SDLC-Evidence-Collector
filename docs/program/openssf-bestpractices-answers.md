# OpenSSF Best Practices Badge — Passing tier answers

Pre-drafted answers for <https://www.bestpractices.dev/> at the
**Passing** tier. The bestpractices.dev form has ~70 questions; the
list below covers every one that is non-obvious from the README.
For each item, the answer is followed by the URL that justifies it
so the reviewer can verify in one click. Replace
`PROJECT_REPO_URL` with the GitHub URL after Phase 1 of the
publication runbook.

## Basics

| Question | Answer | Evidence |
|---|---|---|
| `description_good` | "CLI-first AppSec / DevSecOps tool that ingests SARIF, SBOMs, attestations, model cards, and prompt-injection probe results into a single canonical evidence bundle, evaluates it against an SDLC control catalog (NIST SSDF, OWASP SAMM, FedRAMP 20x KSI, SSDF AI Profile), and emits a signed audit-ready JSON + report." | `README.md` |
| `interact` | "Yes" | `CONTRIBUTING.md` |
| `contribution` | "Yes" | `CONTRIBUTING.md` |
| `contribution_requirements` | "Yes" | `CONTRIBUTING.md` (DCO + signed commits + secure-coding checklist) |

## Change control

| Question | Answer | Evidence |
|---|---|---|
| `repo_public` | "Yes" | `PROJECT_REPO_URL` |
| `repo_track` | "Yes" | git history |
| `repo_interim` | "Yes" | `CHANGELOG.md` + git tags |
| `repo_distributed` | "Yes" | git (distributed VCS) |
| `version_unique` | "Yes" | SemVer + signed tags |
| `version_semver` | "Yes" | `pyproject.toml` + tags |
| `release_notes` | "Yes" | `CHANGELOG.md` per release + GitHub Release notes |
| `release_notes_vulns` | "Yes" | CHANGELOG has a `Security` section per release |

## Reporting

| Question | Answer | Evidence |
|---|---|---|
| `report_process` | "Yes" | `CONTRIBUTING.md` + GitHub Issues + Discussions |
| `report_tracker` | "Yes" | GitHub Issues |
| `report_responses` | "Yes" | Reply SLA documented in `SECURITY.md` |
| `enhancement_responses` | "Yes" | Same as above |
| `report_archive` | "Yes" | GitHub Issues (public archive) |
| `vulnerability_report_process` | "Yes" | `SECURITY.md` |
| `vulnerability_report_private` | "Yes" | Private email + GitHub Security Advisories |
| `vulnerability_report_response` | "Yes; first acknowledgement within 5 business days" | `SECURITY.md` |

## Quality

| Question | Answer | Evidence |
|---|---|---|
| `build` | "Yes" | `pyproject.toml` + setuptools; `python -m build` builds wheel + sdist |
| `build_common_tools` | "Yes" | setuptools + pip + uv (optional) |
| `build_floss_tools` | "Yes" | Apache-2.0 toolchain |
| `test` | "Yes" | `tests/` — 328+ pytest tests |
| `test_invocation` | "Yes" | `python -m pytest` |
| `test_most` | "Yes" | Coverage gate ≥ 80 % (currently 83 %) |
| `test_policy` | "Yes" | `CONTRIBUTING.md` — every PR ships tests |
| `tests_are_added` | "Yes" | git history shows tests alongside features |
| `tests_documentation_added` | "Yes" | `CONTRIBUTING.md` |
| `warnings` | "Yes" | `ruff` + `mypy --strict` enforce zero warnings |
| `warnings_fixed` | "Yes" | Coverage gate forces all warnings to be resolved |
| `warnings_strict` | "Yes" | `mypy --strict` |

## Security

| Question | Answer | Evidence |
|---|---|---|
| `know_secure_design` | "Yes" | `THREAT_MODEL.md` + `docs/adr/` |
| `know_common_errors` | "Yes" | `docs/limitations.md` |
| `crypto_published` | "N/A — the collector does not implement cryptography" | n/a (we use Sigstore/cosign for signing) |
| `crypto_call` | "Yes — uses Sigstore cosign for keyless signing, no custom crypto" | `release.yml` |
| `crypto_floss` | "Yes" | Sigstore / cosign are OSS Apache-2.0 |
| `crypto_keylength` | "Yes" | Sigstore defaults |
| `crypto_working` | "Yes" | cosign verified in CI |
| `crypto_weaknesses` | "Yes" | Sigstore upstream tracks |
| `crypto_pfs` | "N/A" | n/a |
| `crypto_password_storage` | "N/A — no passwords stored" | n/a |
| `crypto_random` | "Yes — uses Python `secrets` / OS RNG only" | code review |
| `delivery_mitm` | "Yes" | PyPI HTTPS + cosign signatures |
| `delivery_unsigned` | "Yes — all releases signed via cosign keyless" | `release.yml` |
| `vulnerabilities_fixed_60_days` | "Yes" | `SECURITY.md` |
| `vulnerabilities_critical_fixed` | "Yes" | `SECURITY.md` |
| `static_analysis` | "Yes" | CodeQL + ruff + mypy in CI |
| `static_analysis_common_vulnerabilities` | "Yes" | CodeQL `security-extended` query suite |
| `static_analysis_fixed` | "Yes" | Release-blocking on critical SAST findings |
| `static_analysis_often` | "Yes" | On every push and weekly |
| `dynamic_analysis` | "N/A — library code, no runtime to exercise dynamically" | `docs/limitations.md` |

## Analysis

| Question | Answer | Evidence |
|---|---|---|
| `documentation_basics` | "Yes" | `README.md`, `docs/`, `THREAT_MODEL.md` |
| `documentation_interface` | "Yes" | `README.md` + `sdlc-evidence --help` |
| `documentation_security` | "Yes" | `SECURITY.md` + `docs/limitations.md` + `THREAT_MODEL.md` |
| `documentation_quick_start` | "Yes" | `README.md` + `docs/ai-evidence.md` |
| `documentation_current` | "Yes" | Owner reviews on each release |
| `documentation_achievements` | "Yes" | `docs/MATURITY_STATUS.md` |
| `accessibility_best_practices` | "N/A — CLI-first, no UI" | n/a |
| `internationalization` | "N/A for the Passing tier" | n/a |

## License

| Question | Answer | Evidence |
|---|---|---|
| `floss_license` | "Yes — Apache-2.0" | `LICENSE` |
| `floss_license_osi` | "Yes" | OSI-approved Apache-2.0 |
| `license_location` | "Yes" | `LICENSE` at repo root |

## After submission

1. Replace the placeholder badge in `README.md` with the assigned
   PROJECT_ID (see Phase 5 of `PUBLICATION-RUNBOOK.md`).
2. Update `docs/MATURITY_STATUS.md` to mark T6.C1 as done.
3. Open a Discussions thread "OpenSSF Best Practices — Passing"
   linking to the badge page so contributors can find it.

## What is missing for Silver tier (deferred)

- Bus factor 2 — currently a single maintainer (`MAINTAINERS.md`).
- Two-factor authentication enforced on all committers — currently
  one committer (the owner).
- Coverage ≥ 90 % — currently 83 %.
- Static analysis must include type errors (already in place via
  mypy strict).

These will be revisited 3-6 months after the public release once
the project has external contributors and a second maintainer.
