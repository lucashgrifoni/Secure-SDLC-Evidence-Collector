# ADR-0002 — Structurally deterministic JSON outputs

- **Status:** accepted
- **Date:** 2026-04-23 (clarified 2026-05-04)

## Context

Auditors and downstream policy engines need to verify that the bundle
they hold has not been tampered with. Cosign's keyless signature
attests to the content at sign time, but consumers also want to confirm
that re-running the collector against the same inputs produces the
same artifact — that is, the bundle is not the product of nondeterministic
ordering, randomized identifiers, or environmental noise.

Strict byte-level determinism would forbid recording any timestamp
inside the bundle, which conflicts with the audit need to know **when**
the evaluation happened. A practical compromise was needed.

## Decision

The bundle is **structurally deterministic**: byte-stable across runs
once four evaluation-time fields are excluded from comparison:

- top-level `bundle_id` (carries a per-run hash suffix)
- top-level `generated_at`
- per-evidence `collected_at`
- per-control `evaluated_at`

JSON serialization sorts keys, uses LF line endings, encodes UTF-8
without BOM, and emits no trailing whitespace. Lists that represent
**sets** of unordered elements are sorted before serialization
(canonical evidence order, control order, gap order).

A CI gate (`github-ci-cd.yml` step `Determinism gate (re-run, normalize, compare SHA-256)`)
re-runs the sample pipeline and asserts that the SHA-256 of the
normalized bundle matches between runs. The README and SECURITY.md
describe the contract in those exact terms.

## Consequences

**Positive**
- Consumers can re-run the collector and prove the inputs and rules
  produced an identical evaluation.
- The 4 volatile fields are explicit and small — easy to strip in
  policy code.
- Drift in any other field becomes a visible CI failure rather than a
  silent inconsistency.

**Negative / accepted**
- The promise is "structural determinism", not "byte determinism".
  Marketing copy must reflect that. We rejected weakening this to
  "best-effort" because it would defeat the audit use case.
- Future schema additions need to consider whether new fields are
  inputs (must be deterministic) or outputs of evaluation time
  (volatile, exempt). This is enforced by extending the strip list in
  the determinism gate, with a comment explaining why.
