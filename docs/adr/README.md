# Architecture Decision Records

These records capture the **non-obvious** architectural and product
decisions taken during the project. The goal is not to document every
choice — small choices live in commit messages — but to record the ones
where the rationale would be easy to forget and expensive to re-derive.

## Index

- [ADR-0001 — Pydantic v2 as the canonical schema layer](./0001-pydantic-v2.md)
- [ADR-0002 — Structurally deterministic JSON outputs](./0002-deterministic-json.md)
- [ADR-0003 — Typer for the CLI](./0003-typer-cli.md)
- [ADR-0004 — Schema-first, evidence-first product framing](./0004-evidence-first.md)
- [ADR-0005 — Replaceable control catalog with org overrides](./0005-control-catalog-override.md)
- [ADR-0006 — CLI command modularization](./0006-cli-command-modularization.md)
- [ADR-0007 — in-toto predicate-type variants](./0007-intoto-predicate-type-variants.md)
- [ADR-0008 — AI evidence types and provenance](./0008-ai-evidence-types-and-provenance.md)
- [ADR-0009 — Risk-weighted release verdict](./0009-risk-weighted-release-verdict.md)
- [ADR-0010 — Reachability as optional SCA evidence field](./0010-reachability-as-optional-sca-evidence-field.md)
- [ADR-0011 — CRA and FedRAMP 20x profiles](./0011-cra-and-fedramp-20x-profiles.md)
- [ADR-0012 — GUAC graph integration](./0012-guac-graph-integration.md)
- [ADR-0013 — Release versioning process](./0013-release-versioning-process.md)
- [ADR-0014 — NIST CSF 2.0 crosswalk for the built-in catalogs](./0014-csf-2-crosswalk-for-built-in-catalogs.md)

## Format

Each ADR follows a compressed [MADR](https://adr.github.io/madr/)
template:

- **Status** — proposed, accepted, deprecated, superseded.
- **Context** — what forced the decision.
- **Decision** — what we chose, in one paragraph.
- **Consequences** — positive and negative effects, including the
  ones we knowingly accept.

ADRs are immutable. To change a decision, write a new ADR that
supersedes the old one and update the `Status` of the original.
