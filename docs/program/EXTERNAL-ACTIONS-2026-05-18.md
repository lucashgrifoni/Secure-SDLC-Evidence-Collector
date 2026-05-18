# External actions for v1.2.0 release — owner checklist

After PR #24 (`chore: post-publication hardening v1.1.1 …`) and PR #25
(`feat: Tier 5 …`) both merge, the project is internally `GO`. The
remaining work is **outside the repository** — none of it can be done
by editing files. This doc lists each action with the exact place to
do it and the verification command.

**Version note.** Originally this checklist targeted `v1.1.1`. Once
the Tier 5 features landed (PR #25 — new CLI commands `enrich`, `vex`,
`statement`, plus the `oscal --kind assessment-results` mode), SemVer
required a minor bump, so the first signed public release is `v1.2.0`.
The PR titles still reference `v1.1.1` for historical accuracy.

Last updated: 2026-05-18 (after the post-publication hardening pass
landed in the PR).

---

## Block A — GitHub Actions billing (BLOCKS Cross-OS gate)

**Why this is first.** The Cross-OS determinism gate did not run on
the last CI run because GitHub returned:
> The job was not started because recent account payments have failed
> or your spending limit needs to be increased.

This affects any job that uses a non-`ubuntu` runner
(`windows-latest`, `macos-latest`). Until billing is resolved, the
`sample-bundle-windows` and `cross-os-determinism` jobs in
`.github/workflows/github-ci-cd.yml` cannot run, and the snapshot
fixture cannot be independently verified by CI.

### Action

1. Open [GitHub Settings → Billing and plans](https://github.com/settings/billing).
2. Check the "Payment information" section for any failed charge.
3. Confirm the Actions spending limit is high enough to cover Windows
   runner minutes (Windows is 2× the Linux rate).
4. Re-run failed jobs on PR #24 from the [Actions tab](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions).

### Verification

`gh pr checks 24` should eventually show:

| Check | Expected |
|-------|----------|
| Cross-OS determinism gate | pass |
| Produce sample evidence bundle (windows) | pass |

---

## Block B — Make the repository public

**Why this matters.** Until the repo is public, every "upload SARIF"
job fails with `Resource not accessible by integration` (because
GitHub code scanning + secret scanning are only free on public repos
without GitHub Advanced Security). Affected jobs on PR #24:

- `SAST - CodeQL (python)` and `(javascript-typescript)`
- `SAST - Semgrep`
- `IaC and Pipeline - Trivy`
- `SCA - Trivy`, `Secrets - Trivy`
- `SCA - Dependency Review (PR)`
- `Secrets History - Gitleaks`
- `SAST - Snyk Code`, `SCA - Snyk Open Source`

These are **expected to fail while private**; they will turn green
automatically the first time CI runs after the repo is made public.

### Action

1. Open [Repository → Settings → General → Danger Zone → Change
   visibility](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/settings).
2. Click "Change repository visibility" → "Make public".
3. Type the repo name to confirm.

### Verification

```bash
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector --jq .visibility
# expected: "public"
```

Then re-run CI on PR #24; every upload-sarif step should succeed.

---

## Block C — Enable Discussions

Closes the only `partial` item on the maturity roadmap (T4.4). Needed
because the existing `stale.yml` and `labels.yml` workflows assume
Discussions are enabled.

### Action

1. Repository → Settings → General → Features → check "Discussions".
2. Optional but recommended: create starter categories (Q&A,
   Show & Tell, Ideas, Announcements).

### Verification

```bash
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json hasDiscussionsEnabled
# expected: {"hasDiscussionsEnabled": true}
```

---

## Block D — Branch protection on `main`

Required for the OpenSSF Scorecard "Branch-Protection" check to score
above zero. Without it the public Scorecard badge will read ~3/10 even
though the rest of the repo is well-engineered.

### Action

1. Repository → Settings → Branches → Add classic branch protection
   rule, or Rulesets.
2. Branch name pattern: `main`.
3. Required minimum: **Require a pull request before merging** (1
   reviewer), **Require status checks to pass before merging** with
   these required checks:
   - `Lint, type-check, and test (py3.12)`
   - `Lint, type-check, and test (py3.13)`
   - `Workflow Lint - actionlint`
   - `Produce sample evidence bundle`
   - `Produce sample evidence bundle (windows)` (after Block A)
   - `Cross-OS determinism gate` (after Block A)
   - `IaC and Pipeline - Trivy` (after Block B)
   - `SAST - Semgrep` (after Block B)
   - `SCA - Trivy` (after Block B)
4. Also enable: **Require branches to be up to date before merging**,
   **Require linear history**, **Include administrators**.

### Verification

```bash
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection
# expected: 200 with required_status_checks populated
```

---

## Block E — PyPI Trusted Publisher + GitHub environment

Required for the `publish-pypi` job in `.github/workflows/release.yml`
to mint the first signed wheel + sdist for `v1.2.0`.

### Action

1. **Create the PyPI project (one time, pre-publish):**
   - Go to [pypi.org/manage/account/publishing/](https://pypi.org/manage/account/publishing/)
   - Click "Add a new publisher" → "Pending project" (since the project
     does not exist on PyPI yet)
   - PyPI project name: `secure-sdlc-evidence-collector`
   - Owner: `lucashgrifoni`
   - Repository: `Secure-SDLC-Evidence-Collector`
   - Workflow filename: `release.yml`
   - Environment name: `pypi`

2. **Create the GitHub `pypi` environment:**
   - Repository → Settings → Environments → New environment → `pypi`
   - Add deployment protection rule: **Required reviewers** = your
     account (so a manual approval is needed before each release
     publish).
   - No environment secrets needed — OIDC handles auth.

### Verification

```bash
# PyPI side (no API for trusted publisher listing; check via UI)
# Project page must exist (will 404 until first publish):
curl -s -o /dev/null -w '%{http_code}\n' https://pypi.org/pypi/secure-sdlc-evidence-collector/json
# 404 is fine pre-publish; after Block H runs it should return 200.

# GitHub environment:
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi --jq .name
# expected: "pypi"
```

---

## Block F — Dependabot HOLDs

Six Dependabot PRs are on HOLD ([`docs/program/dependabot-triage.md`](dependabot-triage.md))
because they touch release/SLSA/CodeQL surfaces. After Blocks A–E land
they can be triaged in order.

Suggested order (lowest risk first):

| PR | Action / version bump | Notes |
|----|-----------------------|-------|
| #16 | `docker/login-action` | Pre-release; ghcr.io login path |
| #11 | `mutmut` | Weekly mutation workflow only |
| #15 | `actions/upload-pages-artifact` | Pages deploy only |
| #17 | `github/codeql-action` | Verify after Block B (CodeQL is now uploading) |
| #13 | `attest-build-provenance` | Release pipeline — test on a dry-run before v1.2.0 |
| #12 | `release-please-action` | Release pipeline — same |

### Verification

```bash
gh pr list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --state open --label dependencies
# expected: 0 after triage
```

---

## Block G — Run Scorecard manually once

The Scorecard workflow is already shipped (`.github/workflows/scorecard.yml`)
and runs weekly + on push to `main`. Trigger it manually once after
Blocks A–D so the public badge becomes meaningful before the v1.2.0
release announcement.

### Action

```bash
gh workflow run scorecard.yml --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --ref main
```

### Verification

```bash
gh run list --workflow=scorecard.yml --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --limit 1
# expected: latest run success

# Or via badge:
curl -s https://api.securityscorecards.dev/projects/github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector | jq .score
# expected: ≥ 7
```

---

## Block H — Cut v1.2.0 signed release

Final step. Only do this after Blocks A–G are green.

### Action

Two options, pick one:

**Option 1 — release-please (preferred)**

The branch `release-please--branches--main` should already exist after
the merge of PR #24, opened automatically by the
`release-please-action` workflow on push to `main`. Merge that PR; the
`release.yml` workflow will then:

1. Build wheel + sdist
2. Sign each artifact with cosign keyless (Sigstore Rekor)
3. Generate CycloneDX SBOM and sign it
4. Upload signed assets to the GitHub Release
5. Publish to PyPI via Trusted Publisher (Block E)
6. Build and push multi-arch container to ghcr.io (signed with
   cosign + SBOM attached as attestation)
7. Generate SLSA L3 provenance via
   `slsa-framework/slsa-github-generator`

**Option 2 — manual tag**

```bash
git checkout main && git pull
git tag -s v1.2.0 -m "Release v1.2.0 — cross-OS determinism + dogfood refresh"
git push origin v1.2.0
```

### Verification

```bash
# GitHub Release
gh release view v1.2.0 --repo lucashgrifoni/Secure-SDLC-Evidence-Collector
# expected: release exists with .whl, .tar.gz, SBOM, SHA256SUMS, signatures

# PyPI
curl -s https://pypi.org/pypi/secure-sdlc-evidence-collector/1.2.0/json | jq -r '.info.version'
# expected: 1.2.0

# Cosign signature (sample, after install)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature <sig-url> \
  <artifact-url>

# Container
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.2.0 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

---

## Block I — Post-release tidy

After v1.2.0 is published and the badges turn green:

1. Update `README.md` so the badge URLs point at `v1.2.0` if any are
   pinned to `v1.1.0`.
2. Optionally flip `step-security/harden-runner` from `audit` to
   `block` after a week of telemetry — track in a separate PR.
3. Close `chore/post-publication-hardening-v1-1-1` branch on remote
   after merge.
4. Move all `melhorias/` legacy redirect doc into archive (the
   2-release deprecation window will have passed by v1.1.2).

---

## Order of operations

```
A (billing) ─┬─→ Block A retry CI on PR #24
             │
B (public) ──┴─→ All upload-sarif jobs go green ──→ Merge PR #24
                                                       │
                                                       ↓
                                              C (Discussions)
                                              D (branch protection)
                                              E (PyPI Trusted Publisher)
                                              F (triage Dependabot HOLDs)
                                              G (Scorecard run)
                                                       │
                                                       ↓
                                              H (cut v1.2.0 release)
                                                       │
                                                       ↓
                                              I (post-release tidy)
```

Blocks A and B can happen in either order, but both must land before
the PR can show a clean green CI matrix. Block C is independent.
Blocks D, E, F, G can run in parallel. Block H is the final gate.
