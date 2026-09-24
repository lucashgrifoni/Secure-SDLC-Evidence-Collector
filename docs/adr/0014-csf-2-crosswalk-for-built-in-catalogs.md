# ADR 0014 — NIST CSF 2.0 crosswalk for the built-in catalogs

- Status: accepted
- Date: 2026-09-24
- Deciders: Lucas Henrique Grifoni

## Context

Auditors increasingly ask which NIST Cybersecurity Framework 2.0 outcomes a
release gate supports. The built-in catalogs speak NIST SSDF (SP 800-218) and
OWASP SAMM, and nothing in the repository said how their controls relate to
CSF 2.0.

Two constraints shape how that can be recorded:

- `ControlDefinition` is `extra="forbid"`. A structured `framework_refs`
  field would change the domain model and the published bundle schema.
- Every bundle records the SHA-256 of the catalog file it was evaluated
  against (`catalog.sha256`), and that value is inside the structural digest.
  Editing the text of a built-in catalog moves the digest of the default
  profile, which this project treats as breaking for anyone pinning
  `verify --expected` (see the 3.0.0 entries in
  `tests/fixtures/sample_release_snapshot.sha256`).

A crosswalk is only useful to an auditor if it can be traced to the
authority it claims. The source used here is NIST's own:

- The **CSF 2.0 Reference Tool export** (Core with informative references),
  from `https://csrc.nist.gov/extensions/nudp/services/json/csf/download?olirids=all`,
  the link NIST's CSF FAQ gives for the informative references. Export
  generated 2026-09-24; SHA-256 of the file retrieved
  `7a34c3ab5e500b380327bb2f9cc8a8ca46fe2bc058ad30d963efc793950995b0`.
  It carries 35 references labelled `SSDF:`, covering 15 SSDF 1.1 tasks.
- **SP 800-218r1 (SSDF 1.2), initial public draft of 2025-12-17.** Its
  reference column still cites CSF 1.1 identifiers (`[NISTCSF]`) for almost
  every task; only the new PO.6 tasks cite CSF 2.0 (`[NISTCSF20]: ID.IM`).

## Decision

Record the crosswalk in this ADR, using only relationships NIST itself lists.
Where NIST lists no CSF 2.0 reference for an SSDF task, the table says so
rather than filling the gap with a judgment call.

Do not edit the built-in catalogs for now. When a release already moves the
default-profile digest for another reason, the references below go into each
control's `description`, the pattern `catalog-ai.yaml` already uses, so the
digest moves once instead of twice.

### Built-in controls

The catalogs map controls at SSDF *practice* level (for example PW.4), while
NIST maps SSDF *tasks* (PW.4.1, PW.4.4). The CSF column is the union over the
tasks NIST maps for that practice, with the task shown in brackets.

| Control | SSDF practice | CSF 2.0 subcategories listed by NIST |
|---|---|---|
| `SSDF-PS.2` | PS.2 | PR.DS-01 [PS.2.1] |
| `SSDF-PS.3` | PS.3 | PR.DS-01, PR.DS-11 [PS.3.1] |
| `SSDF-PW.1` | PW.1 | ID.RA-05 [PW.1.1] |
| `SSDF-PW.4` | PW.4 | GV.SC-03 [PW.4.1]; GV.SC-07, ID.AM-08 [PW.4.1, PW.4.4] |
| `SSDF-PW.6` (SSDF 1.2 catalog only) | PW.6 | none listed |
| `SSDF-PW.7` | PW.7 | none listed |
| `SSDF-PW.8` | PW.8 | none listed |
| `ORG-*`, `SAMM-*` | not SSDF | no NIST reference; `SAMM-DESIGN-TA-1` complements `SSDF-PW.1` by its own description, which is not a NIST mapping |

PR.PS-06 ("Secure software development practices are integrated, and their
performance is monitored throughout the software development life cycle") is
the CSF 2.0 outcome closest to the SSDF as a whole. NIST's informative
references list no SSDF task for it, and this ADR does not add one.

### Every SSDF task NIST maps to CSF 2.0

| SSDF task | CSF 2.0 subcategories |
|---|---|
| PO.1.1 | GV.OC-03 |
| PO.1.2 | GV.OC-03 |
| PO.1.3 | GV.SC-05 |
| PO.2.1 | GV.OC-02, GV.RM-07, GV.RR-02, GV.SC-02 |
| PO.2.2 | PR.AA-06, PR.AT-01, PR.AT-02 |
| PO.2.3 | GV.RR-01 |
| PO.3.3 | PR.PS-04 |
| PO.5.1 | PR.IR-01 |
| PO.5.2 | ID.RA-01, ID.RA-06, ID.RA-07, ID.RA-09, PR.AA-03, PR.AA-05, PR.AA-06, PR.PS-01, PR.PS-02, PR.PS-03 |
| PS.1.1 | PR.AA-05, PR.DS-01, PR.PS-01 |
| PS.2.1 | PR.DS-01 |
| PS.3.1 | PR.DS-01, PR.DS-11 |
| PW.1.1 | ID.RA-05 |
| PW.4.1 | GV.SC-03, GV.SC-07, ID.AM-08 |
| PW.4.4 | GV.SC-07, ID.AM-08 |

A custom catalog that cites SSDF tasks can use this table as is. To
re-derive it, download the export above and collect, for each CSF 2.0
subcategory row, the informative references that start with `SSDF:`.

## Consequences

- The crosswalk is traceable to a named NIST dataset and reproducible from
  it, and adding it changes no bundle, digest or schema.
- Reports and bundles do not show CSF 2.0 identifiers yet; an auditor reads
  them here until the next digest-moving release embeds them in the catalog
  descriptions.
- NIST lists no CSF 2.0 reference for PW.6, PW.7 or PW.8, which cover build
  configuration, code review and analysis, and testing. The gap is NIST's
  mapping, not a claim that those practices support no CSF outcome.
- NIST AI 600-1 is not covered. There is no NIST crosswalk from AI 600-1 to
  the controls in `catalog-ai.yaml`, so mapping them to its twelve risk
  areas is a project judgment and needs its own review before it is written
  down as a mapping.
- When NIST finalises SSDF 1.2 or publishes new informative references, the
  tables must be re-derived from the new export, and this ADR superseded.
