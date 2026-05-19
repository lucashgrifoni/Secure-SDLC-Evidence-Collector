# Governance

How decisions get made in the Secure SDLC Evidence Collector project.
This document is short on purpose: a single-maintainer project does
not need committee structure, and pretending otherwise would be more
dishonest than useful.

## Mission

Be the canonical, **100 % open source** evidence aggregator for
Secure SDLC: collect, normalize, and evaluate evidence produced by
scanners, attestations, and pipelines into auditable bundles consumers
can verify, diff, and sign. Speak the open standards downstream tools
expect (NIST SSDF, OSCAL, OpenVEX, in-toto, CycloneDX, OSV). Do not
become a scanner, a SaaS, or a vendor for a single regulation.

## Decision model

This project uses a **BDFL (Benevolent Dictator For Life)** model.
Today there is one maintainer (see [`MAINTAINERS.md`](./MAINTAINERS.md))
who holds the final word on:

- the bundle schema and what counts as evidence,
- the control catalog defaults and the SSDF / SAMM / ORG mappings,
- the CLI surface (commands, flags, exit codes),
- which standards the project tracks and at what cadence,
- release timing and version semantics.

Every decision is open by default. RFC-style discussion happens in
GitHub Issues or Discussions before non-trivial work begins; the
maintainer summarises and decides in a written comment on the same
thread so the rationale stays linkable.

When the maintainer roster grows past one person, this document gets
updated with a tie-breaking rule (likely: "BDFL holds tiebreak; on
maintainer-disputed bundle-schema changes, the change requires a
written `+2/-0` from non-author maintainers"). Until then, keeping a
single accountable owner is healthier than rubber-stamp consensus.

## What is in scope, what is not

In scope (canonical list lives in
[`docs/MATURITY_ROADMAP.md`](docs/MATURITY_ROADMAP.md)):

- evidence ingestion (parsers, normalizers),
- evidence evaluation (control catalogs, scoring),
- evidence export (JSON, Markdown, HTML, OSCAL, OpenVEX, in-toto),
- evidence enrichment (EPSS, KEV, future risk feeds),
- determinism, reproducibility, and signing integration,
- CLI ergonomics and an optional read-only API for ingestion.

Out of scope:

- becoming a vulnerability scanner of any kind,
- running prompts or executing AI agents,
- a multi-tenant SaaS, hosted dashboard, or telemetry sink,
- proprietary surfaces or paid integrations as required dependencies,
- a custom signing format or in-house EPSS-like model.

The OOS list is normative. Items on it stay off unless the maintainer
documents the change in `MATURITY_ROADMAP.md` and explains why the
constraint moved.

## How changes land

1. **Trivial change** (typo, dead code, doc reflow): direct PR; merge
   when CI is green and one maintainer approves.
2. **Substantive change** (new parser, new exporter, new evidence
   type, scoring change): open an Issue first, agree on the contract,
   then PR. Tests must cover the happy path and at least one failure
   path. CHANGELOG entry required.
3. **Breaking change** (schema removal/rename, CLI flag removal,
   default behavior flip): RFC-style Issue, two-week comment period,
   maintainer sign-off, major-version bump. Migration guidance in the
   release notes is mandatory.
4. **Security fix**: see [`SECURITY.md`](./SECURITY.md). Fix lands
   privately, public CVE + advisory after the patch ships.

## Release cadence

- **Patch** (`x.y.Z`): when a behaviour fix is ready, no minimum
  cadence. Cosign keyless + SLSA L3 provenance on every tag.
- **Minor** (`x.Y.0`): every 4–8 weeks when there is meaningful new
  CLI / catalog / exporter surface. Drafted with the
  `release-please` workflow from conventional commits.
- **Major** (`X.0.0`): only when the project pivots its public claim
  (e.g. v2.0 = OSS-first / standards-aligned). Major-version cuts are
  the exception, not the rhythm.

A version stays supported for one minor cycle after the next one
ships. The collector is a CLI, not a server, so "supported" means
"we'll accept patch-level fixes if they're security-relevant".

## Voting (theoretical)

This section is empty by design until there is a non-BDFL maintainer
roster to vote with. When that happens, the rule will be: simple
majority of active maintainers for non-schema changes; consensus
(no maintainer objects after seven days) for schema changes.

## Funding and sponsorship

The project does not accept directed funding for individual features
because that creates an incentive misalignment with the evidence-first
mission. General sponsorship — GitHub Sponsors, OpenSSF Alpha-Omega,
GitHub Secure Open Source Fund — is welcome and goes to the
maintainer's named account without earmarking. The maintainer
discloses sponsorship sources in `docs/program/community.md` when
that file exists.

## Code of Conduct

See [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Enforcement is the
maintainer's call. Repeat or severe violations result in being banned
from the project's repositories and Discussions; appeals go through
GitHub support, not through the maintainer directly.

## Trademark and naming

"Secure SDLC Evidence Collector" is a descriptive name, not a
trademark. Forks are encouraged; please rename anything that could
be confused with the upstream project (badge, package name on PyPI,
container tag on GHCR).

## License

Apache-2.0 across the whole project. Contributions are covered by
[`CONTRIBUTING.md`](./CONTRIBUTING.md)'s license clause; no separate
CLA is required, since Apache-2.0 already includes the inbound license
grant.
