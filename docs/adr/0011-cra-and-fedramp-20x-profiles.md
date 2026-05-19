# ADR 0011 — CRA + FedRAMP 20x profiles (T6.8)

- Status: accepted (preview; payload formats subject to regulator updates)
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni

## Context

Two regulatory deadlines are landing within three weeks of each
other in 2026:

- **EU Cyber Resilience Act (CRA)** — 2026-09-11. Vendors must
  disclose actively exploited vulnerabilities to ENISA within
  **24 hours** of awareness and ship a machine-readable SBOM with
  every release.
- **FedRAMP 20x (RFC-0024)** — 2026-09-30 deadline for Moderate
  baselines to publish OSCAL machine-readable Assessment Results,
  with revalidation every 3 days.

The bundle already carries SBOM, signature, attestation, SCA, SAST,
secrets, code review, and approval evidence. What it did not carry
was the regulator-shaped projection of that evidence: a CRA-shaped
``exploitation_status`` per finding plus a 24h deadline, and a
FedRAMP-shaped retention stamp.

## Decision

Introduce a thin **profile layer** in
``application.profiles.apply_profile`` that runs after
``build_bundle`` and **annotates evidence** (does not change the
verdict). Two profiles ship today:

- **``cra-2026``** — stamps each evidence with
  ``metadata.cra.exploitation_status`` and
  ``metadata.cra.disclosure_deadline``. The status follows CRA
  vocabulary: ``actively_exploited`` for KEV ransomware + KEV;
  ``known_exploitable`` for EPSS percentile ≥ 0.9 outside KEV;
  ``under_investigation`` otherwise.
- **``fedramp-20x``** — stamps each evidence with
  ``metadata.fedramp.retention_years = 10`` and ``profile = "20x"``
  so the OSCAL Assessment Results exporter has the retention
  metadata at hand.

A new bundled catalog ``catalog-fedramp-20x-ksi.yaml`` ships the KSI
Low+Moderate controls the collector can satisfy with existing
evidence types. Continuous monitoring KSIs that require telemetry
the collector does not ingest are deliberately omitted; operators
can overlay this catalog with their own to cover those.

A new CLI flag ``--profile {none|cra-2026|fedramp-20x}`` selects
the profile at run time.

## Consequences

- **Additive, byte-stable when off.** Default profile is ``none``;
  no evidence is annotated and the bundle is structurally identical
  to pre-T6.8 outputs.
- **CRA payload format is preview-grade.** The ENISA intake format
  is not yet final. Field names follow the regulator's direction
  and will move when ENISA publishes. The structural hash captures
  the annotations so drift is auditable.
- **No verdict change from the profile.** The profile records what
  the regulator wants to see in the evidence; the verdict (`ready`
  / `conditional` / `not_ready`) still comes from
  ``scoring.engine.build_summary`` ± ``apply_risk_mode``.
- **OSCAL exporter unchanged**. The retention stamp lives in
  metadata so the OSCAL Assessment Results path can pick it up
  without bespoke wiring; the wiring itself is a follow-up.

## Alternatives considered

- **Bake CRA fields into the domain model.** Rejected — couples the
  schema to a regulator whose payload is still moving. Metadata
  carries the data without committing the schema.
- **Emit ENISA / FedRAMP JSON natively.** Rejected for v2.0 —
  regulator payload formats are unstable. Annotated bundle is the
  durable intermediate; a downstream converter can render to
  whichever final shape ENISA / FedRAMP publishes.

## Verification

`python -m pytest tests/unit/test_profiles_and_guac.py`. The
deadline math, the exploitation classification, and the FedRAMP
retention stamp are all pinned.
