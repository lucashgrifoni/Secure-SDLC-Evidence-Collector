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

## Tier 5 — Evidence enrichment and supply-chain alignment

Added 2026-05-18 after the post-publication market scan. Each item maps
a 2026 industry signal (EPSS/KEV adoption, EU CRA, FedRAMP 20x, OpenVEX,
in-toto + Sigstore consolidation) to a specific extension that fits the
collector's evidence-first nicho without growing the public surface.

| ID   | Item                                                          | Why it matters                                                                                                              |
|------|---------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| T5.1 | EPSS + CISA KEV enrichment (`sdlc-evidence enrich`)           | Only ~2.3% of CVSS 7+ vulns are exploited. EPSS percentile + KEV flag let release_status reflect real risk, not severity theater. |
| T5.2 | OpenVEX export (`sdlc-evidence vex`)                          | EU CRA (Sept 2026) requires machine-readable VEX next to the SBOM. Avoids forcing consumers to reverse-engineer the bundle. |
| T5.3 | OSCAL Assessment Results export (`oscal --kind assessment-results`) | FedRAMP 20x (Sept 2026) mandates machine-readable AR. Bundle evaluations → OSCAL findings + observations.                  |
| T5.4 | CycloneDX 1.7 parser update (lifecycle phase, TLP, VEX inline)| ECMA-424 standard since 2026; current parser tops out at 1.5.                                                                |
| T5.5 | in-toto Statement v1 wrapper (`sdlc-evidence statement`)      | Bundle becomes natively consumable by Sigstore cosign, GUAC, Kyverno, OPA Gatekeeper. No bespoke envelope code downstream.  |
| T5.6 | SSDF 1.2 catalog upgrade (`catalog-v1.2.yaml`)                | NIST SP 800-218r1 is in final review; current catalog tracks 1.1.                                                            |
| T5.7 | SSDF AI Profile (`catalog-ai.yaml`)                           | SP 800-218A enumerates AI-specific controls (training data lineage, model card, red team). Empty space in the scanner market.|
| T5.8 | EU CRA mode (`--profile cra-2026`)                            | Filters and packages evidence to meet the 24h vuln reporting + 10y retention windows.                                       |
| T5.9 | FedRAMP 20x KSI mapping (`catalog-fedramp-20x-ksi.yaml`)      | Translates internal controls to Key Security Indicators FedRAMP 20x will validate automatically.                            |
| T5.10| GUAC ingestion adapter                                        | Collector becomes a producer of canonical evidence; GUAC remains the graph view across all producers.                       |
| T5.11| Continuous mode (`sdlc-evidence watch`)                       | Daemon that re-runs on webhook events; persists historical bundles. Aligns with continuous ATO and CRA reporting.            |
| T5.12| Risk-based release status (EPSS-weighted)                     | Today `ready/conditional/not_ready` only sees evidence presence. Folding EPSS/KEV in resolves "checklist theater" critique.  |
| T5.13| MCP/agentic evidence types                                    | OWASP MCP Top 10 and Agentic Top 10 (2026) define risks no scanner covers yet. New types: `model_card`, `prompt_injection_test_result`, `mcp_tool_inventory`. |
| T5.14| Multi-VEX consumer (OpenVEX + CycloneDX VEX + CSAF + SPDX)    | Vendors ship different VEX formats; whoever consolidates wins.                                                              |
| T5.15| Market-positioning page                                       | Explicit comparison with Chainguard Enforce / Kusari / Scribe so first-touch users understand the nicho.                    |

**Shipped from Tier 5 (this branch, 2026-05-18):** T5.1, T5.2, T5.3, T5.5.

## Tier 6 — OSS-first standards alignment + AI evidence + sustainability (v2.0)

Added 2026-05-18 after a second market scan. Hard constraint: **100 %
open source**, no proprietary SDKs as required deps, every upstream
project + standard must be free and Apache-2.0 (or compatible) licensed.

Items target a **single v2.0 release** after v1.2.0 publishes. The
x.0 jump is positional (signals the OSS-first / standards-aligned
pivot); all schema changes are additive so a v1.x consumer reading a
v2.x bundle still parses every field it knew. Full plan in
[`docs/program/plan-tier-6-v2.0.md`](program/plan-tier-6-v2.0.md)
(generated from the approved plan at
`~/.claude/plans/fa-a-uma-pesquisa-detalhada-squishy-lovelace.md`).

### Phase A — Standards alignment (~10 days)

| ID    | Item                                                          | Driver                                                                                              |
|-------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| T6.1  | CycloneDX 1.7 parser update                                   | ECMA-424 standard since 2026-03-25. Adds `lifecycles`, `tlp`, `distribution`, inline VEX.           |
| T6.2  | OSV parser + OSV-Scanner SARIF driver row                     | OSV Schema is the OSS-only vulnerability lingua franca; OSV-Scanner v2.3.5 is what teams actually run. |
| T6.3  | in-toto Witness predicate type                                | SBOMit + Witness expect specific predicate types; today T5.5 emits a generic project predicate.     |
| T6.4  | SSDF 1.2 catalog (`catalog-ssdf-1.2.yaml`)                    | NIST SP 800-218 Rev. 1 finalizes 2026 with refined PS.3, PW.7, RV.* tasks.                          |

### Phase B — AI track (~9 days)

| ID    | Item                                                          | Driver                                                                                              |
|-------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| T6.5  | AI catalog + 5 new evidence types + 3 new parsers             | SP 800-218A SSDF AI Profile + OWASP LLM/MCP/Agentic Top 10. Zero OSS scanners ingest these today.   |

### Phase C — Risk-weighted verdict + multi-VEX (~7 days)

| ID    | Item                                                          | Driver                                                                                              |
|-------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| T6.6  | Risk-based release status (`evaluate --risk-mode epss-weighted`) | Today `release_status` only sees evidence presence. Folding EPSS + KEV in closes "checklist theater". |
| T6.7  | Multi-VEX consumer (OpenVEX + CycloneDX VEX + CSAF VEX)       | Vendors ship different VEX dialects; whoever consolidates wins. SPDX VEX deferred (low adoption).   |

### Phase D — Regulatory + Graph (~10 days)

| ID    | Item                                                          | Driver                                                                                              |
|-------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| T6.8  | EU CRA mode (`run --profile cra-2026`) + FedRAMP 20x KSI catalog | EU CRA reporting starts 2026-09-11; FedRAMP 20x mandates OSCAL AR 2026-09-30. Same release.        |
| T6.9  | GUAC ingestion adapter + watch daemon (`[watch]` extra)       | GUAC OpenSSF Incubating; "continuous ATO" is the operational pattern CRA codifies.                  |

### Phase E — Community / sustainability (~6 days, parallel)

| ID    | Item                                                          | Driver                                                                                              |
|-------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| T6.C1 | OpenSSF Best Practices Badge — **passing** tier               | Free, OSS, public signal. Silver deferred to v2.1+ once governance docs have a track record.        |
| T6.C2 | GitHub Secure Open Source Fund application (Apr 2026 cohort)  | Apache-2.0 security tooling qualifies. $10K + Azure credits + mentoring. Backup: Alpha-Omega Tier 2. |
| T6.C3 | Governance + contributor ladder docs                          | Prereq for Silver badge and for the Secure OSS Fund narrative. `GOVERNANCE.md`, `MAINTAINERS.md`.   |
| T6.C4 | Reproducible wheel build (`setuptools-reproducible` or `uv --reproducible`) | Bundle output already deterministic; the wheel itself is not. Closes the last reproducibility gap.  |
| T6.C5 | Rego/Kyverno policy snippets                                  | Admission controllers consuming our bundle work out of the box. Closes "what do I do with this JSON". |

### Tier 6 out of scope (additions to existing OOS list)

- **SPDX VEX consumer** — low real-world adoption; revisit if a major SBOM vendor commits.
- **Source-track SLSA** — spec deferred upstream; Build track L3 is enough.
- **Paid scanner parsers** (Snyk, Veracode, Mend.io, JFrog Xray) — forbidden by the 100 %-OSS constraint.
- **In-house EPSS-like model** — FIRST's feed is free and trusted; rolling our own is rent-seeking.
- **OpenSSF Best Practices Badge Gold tier** — needs multi-maintainer + bug bounty; not a v2.x goal.
- **AI agent execution** — we *ingest* AI evidence; we do not *run* prompts. The watch daemon is a webhook receiver, not an agentic loop.

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
