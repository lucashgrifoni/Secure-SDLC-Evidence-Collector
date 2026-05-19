# ADR 0010 — Reachability as an optional SCA evidence field (§3.2)

- Status: accepted
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni

## Context

SCA scanners report a CVE on every vulnerable dependency, regardless
of whether the vulnerable code path is actually reachable from the
application's entry points. Endor Labs, CodeQL reachability, and
Semgrep Pro all report that 60-80 % of CVEs sit in dead paths. EPSS
+ KEV (Tier 5) capture "exploitable in the ecosystem"; what they do
not capture is **"exploitable in this code base"** — the
reachability layer.

Without a reachability field, consumers cannot filter findings by
the criterion that most reduces noise. Worse, downstream verifiers
trying to assemble a release-readiness narrative have to re-derive
the signal externally and bolt it onto our bundle.

## Decision

Add an **optional** `reachability` field on `NormalizedEvidence`:

```python
class Reachability(_BaseModel):
    status: Literal["reachable", "not_reachable", "unknown"]
    source: str               # "codeql" | "endor-labs" | "semgrep-pro" | "manual"
    method: Literal["data_flow", "function_call", "manual_review"]
    evidence_ref: str | None  # optional pointer to the detailed evidence
```

The collector **records** the upstream verdict. It does **not**
compute reachability itself; that would require static analysis well
outside the collector's scope.

The risk-weighted verdict (ADR-0009) honours the field: a CVE on
evidence flagged `not_reachable` is excluded from the exploitable
count. `unknown` and `reachable` keep the signal so an unknown
verdict cannot quietly suppress a real risk.

## Consequences

- **Additive, byte-stable when absent.** The structural-hash
  normaliser (`application/integrity.py`) strips `reachability: null`
  so pre-§3.2 bundles continue to hash identically to bundles that
  did not opt in.
- **Pluggable.** Any upstream tool can populate the field. The
  domain validates `status` and `method` against canonical sets but
  leaves `source` and `evidence_ref` as free strings so new tools do
  not require a schema bump.
- **Not re-derived by the collector.** Documented in
  `docs/limitations.md`. The collector preserves the verdict; it
  does not invent reachability.

## Alternatives considered

- **Reachability as its own evidence type.** Considered but rejected
  — reachability is an attribute of the SCA finding, not a separate
  artifact. A separate evidence type would force consumers to join
  records by CVE, which adds complexity without information.
- **Boolean `reachable` field.** Rejected — `unknown` is a real and
  common state (no reachability tool ran; tool failed; CVE not yet
  evaluated). Forcing a binary leaks "unknown" as one of the two
  legal values, which is worse than the explicit tri-state.
- **Record reachability inside `metadata`.** Rejected — `metadata`
  is unvalidated free-form; reachability deserves the structural
  guarantees of a typed field (canonical statuses, no typos slipping
  past Pydantic).

## Verification

`python -m pytest tests/unit/test_reachability.py
tests/unit/test_risk_mode.py::test_not_reachable_evidence_suppresses_signal`.
The byte-stability invariant is pinned in
`test_evidence_without_reachability_hashes_like_pre_section_3_2`.
