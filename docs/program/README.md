# Program documentation

This folder consolidates the governance and program-level documents that
support the Secure SDLC Evidence Collector release lifecycle. It is not
product documentation — for usage docs see [`docs/`](../) and the
mkdocs-material site published at `/docs/` of the GitHub Pages deploy.

The folder was created on 2026-05-10 by consolidating the former
`melhorias/` scratch directory. Active governance artefacts kept here;
single-purpose execution notes from the 2026-05-05 publication push
moved to [`_archive/2026-05-05/`](./_archive/2026-05-05/).

## Active artefacts

| File | Purpose |
|---|---|
| [`release-runbook.md`](./release-runbook.md) | Step-by-step runbook for the first signed public release. Owned by the release driver. |
| [`dependabot-triage.md`](./dependabot-triage.md) | Triage log of Dependabot PRs across release/SLSA/CodeQL surfaces. Updated per PR cohort. |
| [`actions-pinning-inventory.md`](./actions-pinning-inventory.md) | Full inventory of GitHub Actions references with SHA pin status, structural exceptions and rationale. |
| [`cross-validation-2026-05-05.md`](./cross-validation-2026-05-05.md) | Cross-validation snapshot reconciling the Codex and Claude reviews of 2026-05-05. Historical baseline; do not rewrite. |

## Archive

The `_archive/2026-05-05/` subfolder preserves the planning scratch from
the 2026-05-05 publication push: prompts handed to Claude Code / Cursor,
the maturity-hygiene plan, the publication plan, external-actions
checklist, and the decision note on keeping `Ideia do projeto.md`. These
documents describe a moment, not the current state — link to them only
as historical references.

## Pointer from the old path

Anything that previously linked to `melhorias/...` continues to work
through the redirect note in [`../../melhorias/README.md`](../../melhorias/README.md).
The redirect file will stay until two minor releases pass without
external complaints about broken links, then will be deleted along with
the `melhorias/` folder.
