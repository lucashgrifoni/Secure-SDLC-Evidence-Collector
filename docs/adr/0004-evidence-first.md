# ADR-0004 — Schema-first, evidence-first product framing

- **Status:** accepted
- **Date:** 2026-04-23

## Context

Most "compliance automation" tools start from a control set (NIST SSDF,
SOC 2, ISO 27001) and ask the user to map their tool output back to
controls. That framing produces dashboards full of partial matches,
unmappable findings, and rubber-stamp checkboxes — the exact failure
mode this project exists to avoid.

## Decision

The product is **schema-first** and **evidence-first**:

- The canonical type is `NormalizedEvidence`, not `Control`. Controls
  are evaluated *against* evidence, not the other way around.
- Every control evaluation must reference at least one evidence ID
  (`evidence_refs`) or be explicitly waived with an exception. There
  is no "passes by assumption" path.
- The release verdict is driven by **gap criticality**, not by the
  raw coverage score. The score informs; the verdict decides.
- Manual attestations are first-class evidence but tagged with lower
  confidence by default, and the report shows that distinction.

## Consequences

**Positive**
- Audit lineage is a property of the data model, not a feature added
  later. Every claim in the report points to an evidence file.
- Adding a new framework (SAMM, ISO, etc.) is a mapping table, not a
  rewrite of scoring logic.
- Marketing claim ("evidence, not opinion") survives engineering
  scrutiny.

**Negative / accepted**
- The model rejects shortcuts that would make demos look better
  (e.g. "passes if no evidence is provided"). This is intentional and
  must remain intentional even under pressure.
- Some controls in NIST SSDF are best satisfied by manual artifacts;
  we accept lower confidence rather than skipping them or pretending
  automation covered them.
