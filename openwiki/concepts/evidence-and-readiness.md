---
type: "concept"
title: "Evidence and release readiness"
description: "Interpret the base gap-driven verdict, optional risk processing and mismatched release anchors."
tags: ["readiness","controls","evidence"]
sources:
  - id: openwiki-source-884501b861b7372e2e6b7d8f
    resource: repo://src/evidence_collector/application/orchestrator.py
  - id: openwiki-source-ec9365904f6d4eb255797a89
    resource: repo://src/evidence_collector/scoring/engine.py
generated: { by: "codex", at: "2026-10-14T18:37:45.397Z" }
verified:
  - by: openwiki/0.7.2
    at: 2026-10-15T00:04:31.320Z
---

# Evidence and release readiness

## Base verdict follows blocking gaps

The base scoring engine returns `not_ready` when a critical blocking gap exists, `conditional` for a high blocking gap or a partial/missing evaluation, and `ready` otherwise. The blocking-gap helper checks the missing required evidence for the matching control; low-criticality gaps are not blocking ([decision logic](../../src/evidence_collector/scoring/engine.py#L109-L161)).

Coverage and confidence are computed separately before being placed in the summary. A score by itself does not select the base release status ([summary construction](../../src/evidence_collector/scoring/engine.py#L200-L221)).

## Additional processing can change the summary

The bundle builder applies risk mode after the base summary. It compares each evidence record's release ID and commit SHA with the requested release anchor. Mismatches are recorded as errors, and a ready summary is degraded to conditional; an already stricter verdict is preserved ([anchor checks](../../src/evidence_collector/application/orchestrator.py#L85-L134), [builder](../../src/evidence_collector/application/orchestrator.py#L185-L215)). `run_pipeline` applies the requested profile afterwards, so interpreting a final bundle requires its profile and risk context as well as the base rule.

## Reader boundary

A bundle records the supplied evidence and the tool's evaluation. It cannot establish that an omitted scanner ran, that a deployment occurred, or that an external approval exists. Inspect provenance, scope and collection errors before relying on the verdict. The [pipeline page](../architecture/release-pipeline.md) identifies where those records enter the bundle.
