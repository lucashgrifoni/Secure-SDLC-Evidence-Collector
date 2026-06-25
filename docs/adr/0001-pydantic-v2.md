# ADR-0001 — Pydantic v2 as the canonical schema layer

- **Status:** accepted
- **Date:** 2026-04-23

## Context

The product's value depends on a single canonical evidence schema:
collectors emit it, the scoring engine consumes it, exporters render
it, and the bundle is signed against it. We needed a layer that:

- enforces a strict structural contract (no silent field drift),
- serializes deterministically to JSON,
- ships its own JSON Schema for downstream validators,
- remains compatible with `mypy --strict`,
- has a credible long-term maintenance trajectory.

Candidates considered: hand-rolled `dataclasses` + custom validators,
`attrs` + `cattrs`, `marshmallow`, Pydantic v1, Pydantic v2.

## Decision

Use **Pydantic v2** as the canonical schema layer. Every domain entity
inherits from `pydantic.BaseModel`, with `model_config = ConfigDict(
extra="forbid", frozen=True)`. The JSON Schema export command
(`sdlc-evidence schema`) builds on `EvidenceBundle.model_json_schema()`,
adding the `$schema`/`$id` keywords (see `evidence_collector.schema`), so
external tools get a self-describing, registry-ready contract without ever
importing Pydantic.

## Consequences

**Positive**
- `extra="forbid"` makes any drift between collectors and consumers a
  hard error instead of a silent data loss.
- Pydantic v2's Rust core is fast enough that bundle build time stays
  well under one second for realistic releases.
- The `model_json_schema()` output is rich enough to support Draft
  2020-12 validators on the consumer side (used by the CI dogfood gate).
- Type-checks cleanly under `mypy --strict` with the `pydantic.mypy`
  plugin enabled.

**Negative / accepted**
- Pydantic v2's API differs significantly from v1; we will not be
  compatible with libraries pinned to v1. Mitigation: pin `pydantic>=2.6,<3.0`
  in `pyproject.toml` and document the version contract.
- Some Pydantic features (custom serializers, computed fields) tempt
  developers to put presentation logic in the schema layer. The team
  agreement is to keep the schema strictly structural; presentation
  goes in `exporters/`.
