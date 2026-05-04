# Maturity Roadmap

This document is the canonical plan for hardening the Secure SDLC Evidence
Collector beyond a stable v1.x release. It complements `CHANGELOG.md`
(what shipped) with **what we still want to ship and why**.

The roadmap is organized into four tiers, ordered by **return on
investment per hour of work**, not by topic. Tier 1 buys the most external
trust signal for the least engineering time; Tier 4 is community and
ecosystem polish that only matters once the lower tiers are already in
place.

Live progress against this plan lives in [`MATURITY_STATUS.md`](./MATURITY_STATUS.md).

---

## Guiding principles

1. **External signals come first.** A public Scorecard score, CodeQL
   alerts on the Security tab, and signed releases tell auditors and
   downstream consumers more than any README claim. Prefer changes that
   produce machine-verifiable evidence.
2. **Test the promises.** Every claim the README makes (deterministic
   bundles, schema stability, control catalog override) should be
   enforced by a CI gate, not just documented.
3. **Don't pay for hypothetical futures.** Skip features that have no
   concrete consumer (multi-tenant API, plugin systems, etc.) until
   someone needs them. List them in Tier 4 so they're not forgotten.
4. **Prefer narrow tools that compose.** `pre-commit` over a custom
   bash gate; `cosign` over an in-house signer; `slsa-github-generator`
   over hand-rolled provenance.

---

## Tier 1 — High impact, low effort (1-2 hours each)

These are the items that move the project from "well engineered" to
"audibly mature" at the lowest cost.

| ID   | Item                                     | Why it matters                                                                                          |
|------|------------------------------------------|---------------------------------------------------------------------------------------------------------|
| T1.1 | OpenSSF Scorecard workflow               | Public health badge auditors and recruiters read at a glance; covers branch protection, deps, signing.  |
| T1.2 | Native CodeQL workflow                   | Surfaces alerts on the repository's Security tab. `security-ci-cd.yml` only emits SARIF, not CodeQL DB. |
| T1.3 | `pre-commit` hooks                       | Today the quality bar is enforced only in CI, so noisy diffs reach reviewers.                           |
| T1.4 | Determinism gate in CI                   | Run `run` twice and compare SHA-256 of `bundle.json`. Determinism is promised; needs to be tested.      |
| T1.5 | `sdlc-evidence doctor` command           | Validates Python version, optional tokens, write perms. Cuts "doesn't work on my machine" reports.     |

## Tier 2 — High impact, medium effort (half a day each)

| ID   | Item                                                | Why it matters                                                                                              |
|------|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| T2.1 | SLSA Build Level 3 provenance                       | `slsa-framework/slsa-github-generator` produces in-toto attestations consumable by Kyverno/OPA/Sigstore.    |
| T2.2 | SBOM of the collector itself, signed                | The tool produces SBOMs for clients but does not publish its own. `cyclonedx-py` + `cosign sign-blob`.      |
| T2.3 | Multi-arch Docker image, signed, with SBOM          | `docker buildx` for `linux/amd64+arm64`, `cosign sign`, `cosign attest`. Enables Mac M-series and Graviton. |
| T2.4 | Mutation testing                                    | 78% line coverage says nothing about assertion strength. `mutmut` reveals tests that pass without purpose.  |
| T2.5 | Structured logs (`structlog`) with `--json-logs`    | Pipelines consume JSON better than Rich tables. Falls back to Rich for TTY humans.                          |

## Tier 3 — Product maturity (1-2 days each)

| ID   | Item                                       | Why it matters                                                                                                 |
|------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------|
| T3.1 | ADRs in `docs/adr/`                        | Decisions like Pydantic v2, deterministic JSON, schema-first dilute in commit messages. Capture them.          |
| T3.2 | Public threat model (`THREAT_MODEL.md`)    | Ironic to ship a Secure SDLC tool without one. Cover SSRF in collectors, parser DoS, token leak, supply chain. |
| T3.3 | Property-based testing with `hypothesis`   | SARIF/SBOM/JUnit have edge cases hand-written cases miss. Generative tests fit deterministic parsers.          |
| T3.4 | mkdocs-material site                       | The README is past 800 lines. GitHub Pages workflow already exists; publish a real technical site.             |
| T3.5 | Python 3.13 in CI matrix                   | `requires-python>=3.12` claims 3.12+; only 3.12 is exercised today.                                            |

## Tier 4 — Scale and community

| ID   | Item                                         | Why it matters                                                                                  |
|------|----------------------------------------------|-------------------------------------------------------------------------------------------------|
| T4.1 | Plugin system for custom parsers             | `entry_points` so third parties add parsers without forking.                                    |
| T4.2 | Optional FastAPI REST surface                | Originally in the plan, deferred from MVP. Useful for platform integrations that POST bundles. |
| T4.3 | OSCAL exporter                               | Auditors speak OSCAL; opens the door to FedRAMP/HITRUST/StateRAMP integrations.                 |
| T4.4 | GitHub Discussions + issue labels + stale-bot| Signals "alive project" — `good first issue`, `help wanted`, abandoned issues auto-closed.      |
| T4.5 | Conventional-commit-driven release tooling   | `release-please` or `semantic-release` so version bumps and changelog entries are mechanical.   |

---

## How items move forward

1. Pick the smallest unfinished tier item.
2. Open a branch, ship the change, validate locally with the same gates
   that CI runs (`ruff`, `mypy`, `pytest`, `actionlint`).
3. Update [`MATURITY_STATUS.md`](./MATURITY_STATUS.md) in the same commit
   so the status doc and the actual repo state never drift.
4. If the item is bigger than expected, split it. The roadmap is allowed
   to grow IDs (e.g. `T2.3a`, `T2.3b`).

---

## Out of scope (recorded so they're not re-litigated)

- **Multi-tenant SaaS deployment** — keeps the project a CLI/Action; no
  scope creep into platform engineering.
- **Web dashboard / analytics** — the bundle is the product; downstream
  visualization is the user's job.
- **Custom signing format** — `cosign` keyless + Sigstore Rekor is the
  industry standard; we don't reinvent it.
