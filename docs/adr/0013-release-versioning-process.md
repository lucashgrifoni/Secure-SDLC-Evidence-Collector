# ADR 0013 — Release versioning process (release-please + a version gate)

- Status: accepted
- Date: 2026-05-25
- Deciders: Lucas Henrique Grifoni

## Context

Versioning was the one part of the release flow that misfired in the
project's history. `git log` shows `chore(main): release 1.3.0 (#33)`
followed by `chore: realign version to 2.0.0 after release-please
regression (#36)`: release-please computed the wrong next version and a
human had to correct it. The root contributing factor was a stale
`.github/.release-please-manifest.json` (it had stuck at `1.2.0`), which
let the four version sources drift apart:

* `pyproject.toml` `[project].version`
* `src/evidence_collector/__init__.py` `__version__`
* `.github/.release-please-manifest.json`
* `CHANGELOG.md` top released heading

Since then release-please has cut `2.0.1 → 2.0.5` cleanly, and #45 fixed a
separate problem (release-please must publish **non-draft** releases so the
tag that triggers `publish-pypi.yml` is actually created). But the choice
of "release-please owns versioning" was never written down, and nothing in
CI prevents the four sources from silently drifting again.

## Decision

**Keep release-please as the single authority for versioning and release
tagging**, and make the previously-implicit invariant explicit with a CI
gate.

* release-please owns the version bump across all four sources (the three
  code/config files carry an `x-release-please-version` marker; the
  CHANGELOG is generated from Conventional Commits). Humans do not edit
  version numbers by hand.
* A new **version-consistency gate** (`scripts/check_version_consistency.py`,
  run by the `Version consistency gate` job in `github-ci-cd.yml`) fails CI
  if the four sources disagree. It deliberately does not consult the git tag:
  release-please derives the tag from these files, so keeping the files
  honest is what prevents a bad tag.
* Authentication stays on the dedicated release-please GitHub App token
  (not `GITHUB_TOKEN`), because tags pushed by `GITHUB_TOKEN` do not trigger
  `publish-pypi.yml` and "Allow Actions to create/approve PRs" is off.

## Consequences

- **The 1.3.0-class regression now fails fast.** A drift between the four
  sources turns into a red check on the PR instead of a published bad tag.
- **Versioning stays hands-off.** Contributors write Conventional Commits;
  they never touch a version string. This is less error-prone than manual
  tagging but means the team must keep commit types honest (a `feat:` vs
  `fix:` mistake changes the computed bump).
- **One known rough edge remains, handled manually.** release-please can
  re-insert the new version heading above `## [Unreleased]` in the
  CHANGELOG; the maintainer reorders it on the release PR before merge (done
  for 2.0.4 and 2.0.5). The gate does not enforce Keep-a-Changelog ordering,
  only version equality. If this recurs, a follow-up ADR can automate it.
- **Release-only commits still need judgement.** Because `ci`/`docs` commits
  are not hidden, release-please opens release PRs for doc/CI-only changes
  (e.g. #56 for 2.0.6). The standing rule is to hold those until they ride
  along with a real code change; the gate does not decide that.

## Alternatives considered

- **Manual signed tags (drop release-please).** Rejected. v2.0.0 shipped
  this way and it is predictable, but it puts the full burden of bumping all
  four sources, writing the CHANGELOG, and signing the tag on the maintainer
  every release — which is exactly the manual surface where the original
  drift happened. release-please + the consistency gate keeps the automation
  while closing the failure mode the manual process was meant to avoid.
- **Single source of version (e.g. derive everything from the tag at build
  time).** Rejected for now. It would remove the drift entirely, but it
  fights release-please's file-based model and the `x-release-please-version`
  extra-files mechanism the project already relies on. Worth revisiting only
  if the manual CHANGELOG-reorder rough edge becomes a recurring cost.

## Verification

`python scripts/check_version_consistency.py` exits 0 on a consistent tree
(currently `2.0.5`) and exits 1 with a per-source diff when any source
disagrees. The `Version consistency gate` job runs it on every PR and push.
