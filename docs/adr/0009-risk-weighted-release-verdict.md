# ADR 0009 — Risk-weighted release verdict (epss-weighted mode)

- Status: accepted
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni

## Context

The default presence-based verdict (`scoring.engine.build_summary`)
blocks releases when required evidence is missing. That captures
SDLC hygiene but is blind to whether the actually-present CVEs are
exploitable. After Tier 5 enriched the bundle with EPSS + KEV signal
(via `--enrich`), we had the data needed to re-derive the verdict by
real-world exploitability — but the data was not yet feeding the
release decision.

The classical "checklist theater" critique applies here: a bundle
with 100 % evidence coverage and three KEV-listed ransomware CVEs is
still `ready` under the default mode.

## Decision

Add an **opt-in** risk-weighted verdict mode invoked via
`sdlc-evidence run --risk-mode epss-weighted`. When active, the
verdict is re-derived in `scoring.risk.apply_risk_mode` using the
EPSS / KEV signal:

| Condition | Effect on `release_status` |
|---|---|
| Any CVE in CISA KEV with `known_ransomware` | Forced to `not_ready` (overrides base) |
| Any CVE in KEV (without ransomware) OR any CVE with EPSS percentile ≥ threshold | Downgraded to at least `conditional` |
| No exploitable CVE | Base verdict preserved |

The threshold defaults to `0.70` (70th EPSS percentile) and is
configurable via `--epss-percentile-threshold`. The bundle carries
the rationale in a new optional `Summary.risk_assessment` block so
auditors can reconstruct the decision.

Reachability is honoured: a CVE on evidence flagged
`reachability.status == "not_reachable"` is removed from the
exploitable count (see ADR-0010). `unknown` and `reachable` keep
the signal.

## Consequences

- **Default off, byte-stable.** When `--risk-mode off` (default), the
  bundle is structurally identical to pre-T6.6 outputs once the
  structural-hash normaliser strips the null `risk_assessment` field
  (see `application/integrity.py`).
- **Enriched bundles are not byte-stable across EPSS/KEV feed
  refreshes.** Documented in `docs/limitations.md`. The structural
  hash deliberately captures `epss_feed_date`, `epss_model_version`,
  and `kev_feed_date` so feed (or EPSS model-version) updates surface
  as drift.
- **Only downgrades, never upgrades.** A `not_ready` base verdict is
  not promoted to `ready` even when no CVE is exploitable. Missing
  evidence is its own gap — risk weighting cannot wave hand it away.
- **Composable with `compare`.** `sdlc-evidence compare` can be used
  to diff two enriched bundles and reason about whether the verdict
  drifted because of new CVEs or because the EPSS feed moved. Since
  2026-08-07 `compare` states this explicitly: when the two bundles
  carry different `epss_model_version` values it reports EPSS model
  drift, in the table output and under the `epss` key of the JSON
  contract.

### The default threshold was calibrated under EPSS v4

EPSS **v5 went to production on 2026-06-15** (feed header
`#model_version:v2026.06.15`). It is a re-fit of the model, not a
re-scoring under the old one, so **scores and percentiles are not
comparable across model versions**: a CVE can move without anything
about the CVE, the dependency, or the release having changed.

Two consequences for anyone operating this mode:

- The `0.70` default for `--epss-percentile-threshold` was chosen
  against v4 output. It is not automatically wrong under v5, but it is
  not evidence-backed under v5 either — re-check it against your own
  finding population before treating it as tuned.
- A release-over-release comparison that straddles the v4→v5 boundary
  cannot attribute score movement to posture. Re-enrich both bundles
  under a single model before drawing a conclusion; `compare` now warns
  when you have not.

## Alternatives considered

- **Always-on risk weighting.** Rejected — breaks backward
  compatibility and forces every consumer to keep EPSS / KEV feeds
  fresh even when they only need the hygiene signal.
- **Per-control thresholds in the catalog.** Tempting but
  premature — surfaces complexity at the catalog level before we have
  evidence operators want it. A future ADR can promote thresholds
  into the catalog if needed.
- **Score-based downgrade (coverage × confidence × exploitability).**
  Rejected — composite scores hide the signal. The verdict is binary
  per CVE (exploitable or not); aggregating to a number adds no
  information for the auditor.

## Verification

`python -m pytest tests/unit/test_risk_mode.py` exercises the
precedence (KEV ransomware → not_ready, exploitable → conditional,
clean → preserved), the reachability suppression path, threshold
override behaviour, and the "off mode returns input unchanged"
invariant.
