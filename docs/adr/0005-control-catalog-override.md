# ADR-0005 — Replaceable control catalog with org overrides

- **Status:** accepted
- **Date:** 2026-04-23

## Context

Different organizations have different "minimum Secure SDLC". A FinTech
under PCI may require strong release approval and rollback evidence; a
public OSS library may not have either. Hard-coding our 13-control
default catalog as the only possible input would push every adopter
into a fork.

## Decision

The default catalog ships in `src/evidence_collector/controls/data/*.yaml`
and is loaded by `default_catalog()`. Every consumer command exposes a
`--catalog` option that takes a YAML file path. When provided, that
file fully replaces the built-in catalog — there is no merge, no
inheritance, no partial override. Any control IDs the consumer wants
from the default catalog must be copied into their override file.

The schema for the override file is published in
`docs/bundle_schema.md` and validated by Pydantic at load time, so a
malformed override fails loudly at startup instead of silently.

## Consequences

**Positive**
- Adopters can run the tool against their own minimum baseline without
  forking the codebase.
- The default catalog stays opinionated; organizations who disagree
  with our weighting do not need to argue, they override.
- Failure mode is loud — a malformed override file does not silently
  fall back to defaults.

**Negative / accepted**
- We rejected merge semantics. They are convenient but produce hidden
  precedence rules that make support questions ("why is this control
  evaluating different than I expect?") much harder to answer.
- Adopters who want to *extend* the default rather than replace it
  must duplicate the default content in their override. We provide
  the canonical YAML in the repo so the duplication cost is small.
