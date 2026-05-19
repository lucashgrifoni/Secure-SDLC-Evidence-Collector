# ADR 0012 — GUAC graph integration (T6.9)

- Status: accepted (GUAC pre-1.0; container format may evolve)
- Date: 2026-05-19
- Deciders: Lucas Henrique Grifoni

## Context

GUAC (Graph for Understanding Artifact Composition,
https://docs.guac.sh) is the OpenSSF Incubating canonical graph
backend for supply-chain metadata. It ingests upstream documents
(SBOMs, SARIF, attestations, …) and stitches them into a graph that
answers "what depends on what, who built what, which CVEs affect
which artifacts" across an organisation.

Without an adapter, a consumer who wants to load a Secure SDLC
Evidence Collector bundle into GUAC has to disassemble the bundle
manually and feed each raw document to ``guacone collect files``.
That is fragile (paths leak filesystem layout) and slow (the bundle
already knows what each artifact is).

## Decision

Add a thin **GUAC collector container** exporter at
``exporters.guac.build_guac_collection`` plus a CLI command
``sdlc-evidence guac BUNDLE_PATH --output guac.json``. The
container is a single JSON document with:

* a stable release envelope (`application`, `repository`,
  `release_id`, `commit_sha`),
* one ``documents[]`` entry per evidence with the GUAC document
  ``type`` (sbom / sarif / attestation / vex / evidence), the
  source artifact path, the integrity hash, and the CVE list when
  populated.

GUAC's own ingest format is **the document itself**; the container
here is a routing layer that lets ``guacone collect files`` walk
the release in one shot instead of N hand-coordinated invocations.

## Consequences

- **Container is intentionally minimal.** GUAC's API is still
  pre-1.0; a richer wire format would have to change every time
  GUAC bumps. The container records the bundle's release context
  and points at the raw documents, which is the smallest payload
  that lets GUAC do its job.
- **No code changes when GUAC bumps.** As long as GUAC's collector
  family keeps accepting the upstream documents (SBOMs in
  CycloneDX/SPDX, SARIF, in-toto attestations), the container
  format survives. A future ADR can bump the container version.
- **Bundle is the source of truth, not the container.** The GUAC
  container is a projection; consumers that need the full evidence
  graph keep reading the bundle directly.

## On the ``watch`` daemon

The roadmap pairs T6.9 with a ``sdlc-evidence watch`` daemon
(webhook receiver, durable cursor, delta bundles). That subcommand
is deferred from v2.0 to v2.1 because:

1. It needs an optional extra (``[watch]``) with FastAPI + uvicorn
   + watchdog, which complicates the runtime contract.
2. Durable cursor state introduces persistence — the collector has
   stayed file-only on purpose.
3. The GUAC adapter already gives the graph use case a clean entry
   point; the watch daemon is a continuous-ATO accelerator, not a
   v2.0 blocker.

The deferral is documented in `docs/limitations.md §17 — Watch
daemon postponed to v2.1`.

## Alternatives considered

- **Native GUAC GraphQL ingestion.** Rejected — couples us to a
  pre-1.0 API and forces the collector to ship a HTTP client where
  a JSON file works.
- **Emit per-evidence files into a directory tree.** Rejected — the
  bundle already groups the evidence; a flat tree loses the release
  envelope.

## Verification

`python -m pytest tests/unit/test_profiles_and_guac.py
::test_guac_adapter_emits_one_document_per_evidence` and the
fallback test. A future end-to-end smoke test will run
`guacone collect files guac.json` against a local GUAC stack; that
is tracked under the v2.0 release-readiness checklist.
