# Public launch runbook — Secure SDLC Evidence Collector v2.0.0

This runbook is the operational checklist for the **single public
release** the project ships once v2.0 is functionally complete. The
owner (Lucas Henrique Grifoni) executes the steps below; the
collector itself cannot drive most of them because they live in
external UIs (GitHub Settings, PyPI, bestpractices.dev).

> **Pre-flight invariant.** Sprints 1-5 must be green before this
> runbook starts: 328+ tests passing, mypy strict zero, ruff zero,
> coverage ≥ 80 %, reproducible wheel gate green, all ADRs (0001-
> 0012) merged into `main`. Verify with `python -m pytest && python
> -m mypy src/evidence_collector && python -m ruff check src tests`.

## Phase 0 — Pre-flight (1 hour, owner alone)

- [ ] Pull `main` and confirm clean tree: `git status` is empty.
- [ ] Re-run the full test suite: `python -m pytest -q` → expect
      328+ passing.
- [ ] Confirm `pyproject.toml` `version = "2.0.0"` and CHANGELOG.md
      has the v2.0.0 entry promoted from `[Unreleased]`.
- [ ] Sanity-check the GitHub workflows in `.github/workflows/`
      with `python -c "import yaml; [yaml.safe_load(open(f)) for f in
      __import__('pathlib').Path('.github/workflows').glob('*.yml')]; print('OK')"`.
- [ ] Confirm the bundled catalogs load:
      ```bash
      python -c "
      from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog
      for name in ('catalog-ssdf-1.2.yaml', 'catalog-ai.yaml', 'catalog-fedramp-20x-ksi.yaml'):
          assert load_catalog(bundled_catalog_path(name)), name
      print('catalogs OK')
      "
      ```

## Phase 1 — GitHub repo configuration (15 min, owner alone)

UI-only or `gh` CLI; the runbook prefers `gh` so the changes are
auditable.

### 1.1 Make the repository public

> ⚠️ Irreversible — once public, history is cached by search engines.
> Confirm `git log` does not contain accidental secrets:
> ```bash
> python -m pip install gitleaks-py  # or use the standalone CLI
> gitleaks detect --source . --no-banner --redact
> ```

```bash
gh repo edit lucashgrifoni/Secure-SDLC-Evidence-Collector \
  --visibility public --accept-visibility-change-consequences
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json visibility
# expect: {"visibility":"public"}
```

### 1.2 Branch protection on `main`

```bash
gh api -X PUT repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection \
  -f required_status_checks[strict]=true \
  -f required_status_checks[contexts][]=ci \
  -f required_status_checks[contexts][]=security-ci \
  -f required_status_checks[contexts][]=codeql \
  -f required_status_checks[contexts][]=scorecard \
  -f required_status_checks[contexts][]=policy-tests \
  -f enforce_admins=true \
  -f required_pull_request_reviews[required_approving_review_count]=1 \
  -f required_pull_request_reviews[dismiss_stale_reviews]=true \
  -f restrictions=null \
  -f allow_force_pushes=false \
  -f allow_deletions=false
```

### 1.3 Discussions, code scanning, secret scanning

```bash
gh api -X PATCH repos/lucashgrifoni/Secure-SDLC-Evidence-Collector -f has_discussions=true
# Code scanning + secret scanning enable themselves once the repo
# becomes public; verify in Settings → Code security & analysis.
```

### 1.4 GitHub environment `pypi`

```bash
gh api -X PUT repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi \
  -f wait_timer=0 \
  -F prevent_self_review=false \
  -F deployment_branch_policy[protected_branches]=true \
  -F deployment_branch_policy[custom_branch_policies]=false
```

## Phase 2 — PyPI (10 min, owner alone, **UI-only**)

`gh` cannot drive PyPI. These steps require the owner in a browser.

- [ ] Create the project at <https://pypi.org/manage/projects/>
      → New project → name `secure-sdlc-evidence-collector`.
- [ ] Configure Trusted Publisher at
      <https://pypi.org/manage/account/publishing/>:
      - **Owner**: `lucashgrifoni`
      - **Repository**: `Secure-SDLC-Evidence-Collector`
      - **Workflow filename**: `release.yml`
      - **Environment**: `pypi`
- [ ] Verify: `pip index versions secure-sdlc-evidence-collector`
      returns the project page (no versions yet).

## Phase 3 — Dependabot triage (5-30 min, owner)

Re-run `dependabot-triage.md`: pull the actual open PR list with
`gh pr list --state open --label dependencies` and triage each
against the rules in `docs/program/dependabot-triage.md`. The
v2.0.0 release must not block on a Dependabot bump that touches
release.yml or scorecard.yml.

## Phase 4 — Cut v2.0.0 (5 min, owner triggers; CI does the rest)

> ⚠️ **Once a tag pushes, release.yml runs and Trusted Publisher
> publishes to PyPI. Make sure Phase 2 is complete before pushing
> the tag.**

```bash
git checkout main && git pull
git tag -s v2.0.0 -m "v2.0.0 — Tier 6 / Phases A-E + AI track + CRA/FedRAMP + GUAC"
git push origin v2.0.0
# watch the workflow:
gh run watch
```

### Expected artifacts after `release.yml` is green

- [ ] GitHub Release `v2.0.0` with:
      - `secure_sdlc_evidence_collector-2.0.0-py3-none-any.whl`
      - `secure_sdlc_evidence_collector-2.0.0.tar.gz`
      - `bundle.json` (self-release evidence pack, signed)
      - `report.md`, `summary.html`
      - `*.intoto.jsonl` (SLSA provenance)
      - `*.sig`, `*.crt` (cosign keyless artifacts)
- [ ] PyPI: <https://pypi.org/project/secure-sdlc-evidence-collector/2.0.0/>
- [ ] GHCR: `ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v2.0.0`
      (multi-arch amd64 + arm64; cosign-signed)
- [ ] Reproducible wheel gate (T6.C4) green inside the build job.

### Validation after publication

```bash
# fresh venv
python -m venv /tmp/check && /tmp/check/bin/python -m pip install --quiet \
  "secure-sdlc-evidence-collector==2.0.0"
/tmp/check/bin/sdlc-evidence --version  # expect: 2.0.0

# GHCR + cosign keyless verify
docker pull ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v2.0.0
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v2.0.0 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Phase 5 — OpenSSF Best Practices Badge (45 min, owner, **UI-only**)

The collector cannot fill in the bestpractices.dev form. Use the
pre-drafted answers in
[`docs/program/openssf-bestpractices-answers.md`](./openssf-bestpractices-answers.md)
and paste each into the corresponding question. Targets the
**Passing** tier; Silver is deferred until bus factor reaches 2.

After submission:

```bash
PROJECT_ID="$(prompt user for ID assigned by bestpractices.dev)"
# Update README.md: replace the placeholder badge with the real one.
sed -i "s|registration%20pending|projects/${PROJECT_ID}/badge|" README.md
# Replace placeholder URL too.
sed -i "s|registration%20pending|projects/${PROJECT_ID}|" README.md
git add README.md
git commit -m "chore: openssf best practices passing tier (project ${PROJECT_ID})"
git push
```

## Phase 6 — Post-launch verification (24h soak, owner)

- [ ] Scorecard score visible at
      <https://scorecard.dev/viewer/?uri=github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector>
      and ≥ 7.0.
- [ ] First `pip install secure-sdlc-evidence-collector` from a
      fresh machine works without auth.
- [ ] First Discussions thread seeded by the owner — at least 3
      threads in the first week so the page does not look dead.
- [ ] `docs/MATURITY_STATUS.md` updated with the new public state.

## Rollback plan (T6.C4 carry-over)

If `release.yml` fails partially:

| Failure | Action |
|---|---|
| cosign keyless / Fulcio OIDC failure, no artifact published yet | Delete tag local + remote, fix `permissions: id-token: write` / environment, recreate tag. |
| PyPI 403 (Trusted Publisher) | Confirm trio (owner / repo / workflow / env) matches exactly. Do **not** yank — if a partial publish happened, abort to v2.0.1. |
| GHCR multi-arch failure (one arch missing) | Delete the partial version via `gh api -X DELETE /user/packages/container/<name>/versions/<id>` and retry. |
| **Any artifact already published to PyPI** | Abort v2.0.0 and re-tag as v2.0.1. PyPI does not allow re-uploads of a yanked version. |

Document every incident in `docs/program/release-incidents.md`
(create the file if it does not yet exist) — auditors expect a
maintained log.

## Phase 7 — Communication (1 week, owner)

- [ ] Update LinkedIn / Bluesky / Mastodon with the release link.
- [ ] Submit a talk proposal to OpenSSF Day (next CFP window).
- [ ] Apply to GitHub Secure Open Source Fund (next intake) or
      Alpha-Omega Tier 2 after 6 months of public adoption.
- [ ] Reach out to one contact per ecosystem (Chainguard / Scribe /
      Kusari / GUAC core) with the comparison page and ask for
      review.

## Done criteria

- [ ] Repository public.
- [ ] v2.0.0 tag pushed and release.yml green.
- [ ] PyPI publication, `pip install` works.
- [ ] GHCR multi-arch image pullable and cosign-verifies.
- [ ] Scorecard ≥ 7.0.
- [ ] OpenSSF Best Practices badge visible at Passing tier.
- [ ] README updated with all real badges (no placeholders).
- [ ] First three Discussions threads seeded.
- [ ] `docs/MATURITY_STATUS.md` updated with the post-launch state.
