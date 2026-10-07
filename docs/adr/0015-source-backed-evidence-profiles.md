# ADR 0015 — Source-backed evidence annotations and bounded profiles

- Status: accepted for implementation; publication of a collector release pending
- Date: 2026-10-07
- Decider: Lucas Henrique Grifoni
- Supersedes: ADR 0011 profile annotations; corrects ADR 0008 references
- Implements: ADR 0014 descriptions

## Decision

Use the published CISA 2026 list and G7 AI SBOM paper to report presence states,
not compliance. Keep unsupported format fields explicit. Retain the legacy
2025 keys for compatibility. Add no evidence type or framework enum.

Use release-bound operator context for CRA clocks and SRP 1.4 completeness.
KEV and EPSS are intelligence inputs, not product-specific exploitation,
awareness or legal applicability. The profile does not submit a notification.
Context-derived deadlines participate in integrity checks.

Pin the FedRAMP CR26 rules and offer six supporting-evidence KSI controls as
ORG_INTERNAL project mappings. Keep the old catalog's identifiers available
as legacy internal checks. Remove the unsupported retention duration.

Replace invented AI task IDs with actual SP 800-218A references. Model-card
support uses PO.1.2 N1, which explicitly discusses model documentation.
Safety/bias and deployed-agent inventory remain project policy. Do not compose
an apparent official AI 600-1 crosswalk from different publications.

Include the preserved CSF 2.0 references in catalog descriptions now that the
CISA change already intentionally moves the default digest. Practice-level
references are unions over the tasks in the preserved SSDF 1.1 export.

## Scope and rejected alternatives

B1 automatic BOD/SSVC decisions are deferred: deployed exposure and decision
inputs do not come from a release artifact alone. A dedicated assertion reader
requires a separate input/schema review. E1 automatic GPAI conformance is
dropped from this release; manual review can use existing evidence without
treating it as complete legal documentation. D3 is limited to source corrections.

No regulator-native submission payload, regulatory certification, new scanner,
watch service, evidence predicate language or schema expansion is introduced.

## Verification and migration

Tests cover all 17 CISA and 50 G7 keys, paired hashes, root components, SPDX
limitations, source identifiers, CRA release binding, field stages, calendar
clocks and deadline tampering. The existing snapshot changes intentionally.
The typed bundle schema stays at 2.1.0; catalog and metadata hashes change.

[Migration and limitations](../evidence-profile-migration.md) records flags,
compatibility, clocks, manual review boundaries, concurrency recovery and sources.
[CR26 provenance](data/0015-fedramp-cr26-provenance.json) records the official
rules version, commit and selected KSI/SP 800-53 references.
