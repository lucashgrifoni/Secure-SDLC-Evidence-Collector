---
type: "architecture"
title: "Release evidence pipeline"
description: "Follow local collection through catalog evaluation, anchor checks and report persistence."
tags: ["architecture","evidence","bundle"]
verified:
  - by: openwiki/0.7.2
    at: 2026-10-14T18:37:45.397Z
sources:
  - id: openwiki-source-884501b861b7372e2e6b7d8f
    resource: repo://src/evidence_collector/application/orchestrator.py
  - id: openwiki-source-77a871f24ea5ad3f7c1d3f10
    resource: repo://src/evidence_collector/cli/commands/collect.py
  - id: openwiki-source-80850f15ccaa0f35fa597152
    resource: repo://src/evidence_collector/cli/commands/evaluate.py
  - id: openwiki-source-7efc0d0dbf4b42d5433047b3
    resource: repo://src/evidence_collector/collectors/local.py
  - id: openwiki-source-65ae12528fd4a27cb80d2539
    resource: repo://tests/integration/test_collect_evaluate_split.py
generated: { by: "codex", at: "2026-10-14T18:37:45.397Z" }
---

# Release evidence pipeline

## Collection owns filesystem discovery

`LocalArtifactCollector` receives separate artifact, attestation and exception directories. Its traversal resolves file paths before deduplication, so overlapping input directories do not ingest the same file twice. Invalid input directories become explicit collection errors ([collector](../../src/evidence_collector/collectors/local.py#L153-L253)). This state differs from evidence that was never supplied.

## Orchestration owns the bundle

`run_pipeline` appends optional externally supplied evidence and exceptions to the local collection. It carries local collection errors into `build_bundle`, applies the profile, creates the output directory and calls `export_report_set` ([pipeline](../../src/evidence_collector/application/orchestrator.py#L219-L280)). Collectors do not choose the final release verdict.

`build_bundle` loads the catalog with provenance, evaluates controls with application/release context, builds the summary and applies risk mode. It stores control evaluations, gaps, exceptions and collection errors in the returned bundle ([builder](../../src/evidence_collector/application/orchestrator.py#L174-L216)).

## The split flow keeps failure evidence

For collection followed by later evaluation, the current CLI uses a JSON envelope carrying both evidence and collection errors. The integration tests assert that a broken SARIF input survives the boundary into the evaluated bundle ([split-flow tests](../../tests/integration/test_collect_evaluate_split.py#L90-L110)). Follow this contract rather than treating the collection output as only a list of records.

See [readiness semantics](../concepts/evidence-and-readiness.md) for decisions and [CLI and CI](../workflows/cli-and-ci.md) for process outcomes.
