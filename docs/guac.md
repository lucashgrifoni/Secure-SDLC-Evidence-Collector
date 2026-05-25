# Loading bundles into GUAC

The Secure SDLC Evidence Collector ships a thin adapter that turns a
bundle into a `guac-collect` container — a single JSON file that
[GUAC](https://docs.guac.sh) can ingest in one shot, without the
consumer having to disassemble the bundle and feed each SBOM, SARIF
run, or attestation to `guacone collect files` by hand.

## Why

GUAC (Graph for Understanding Artifact Composition) is the OpenSSF
Incubating canonical graph backend for supply-chain metadata. It
ingests upstream documents — SBOMs, SARIF, in-toto attestations, VEX
— and stitches them into a graph that answers cross-repository
questions: what depends on what, who built what, which CVEs affect
which artifacts.

A bundle already knows what each artifact is (its evidence type,
subject, integrity hash, CVE list). The GUAC adapter is a routing
layer: instead of N hand-coordinated `guacone` invocations, it emits
one container that walks the whole release. The decision and its
trade-offs are recorded in
[ADR-0012 — GUAC graph integration](./adr/0012-guac-graph-integration.md).

The bundle stays the source of truth. The GUAC container is a
projection — consumers that need the full evidence graph keep
reading `bundle.json` directly.

## Generating a GUAC collection

```bash
sdlc-evidence guac output/sample_release/bundle.json \
  --output output/sample_release/guac-collection.json
```

The command reads a `bundle.json`, builds the container, and writes
it to `--output` (default `guac.json`).

The container shape:

```json
{
  "format": "guac-collect",
  "version": "1.0",
  "source": "secure-sdlc-evidence-collector",
  "release": {
    "application": "payments-api",
    "repository": "acme/payments-api",
    "release_id": "2026.04.10",
    "commit_sha": "abcdef1234567890"
  },
  "documents": [
    {
      "type": "sbom",
      "evidence_id": "ev-003",
      "evidence_type": "sbom",
      "subject": { "type": "artifact", "ref": "payments-api:2026.04.10" },
      "status": "generated",
      "producer": "cyclonedx",
      "artifact_path": "artifacts/sbom.cdx.json",
      "integrity_hash": "sha256:..."
    },
    {
      "type": "sarif",
      "evidence_id": "ev-001",
      "evidence_type": "sast_scan",
      "subject": { "type": "repository", "ref": "acme/payments-api" },
      "status": "passed",
      "producer": "semgrep",
      "artifact_path": "artifacts/semgrep.sarif",
      "integrity_hash": "sha256:..."
    }
  ]
}
```

Each `documents[]` entry carries the GUAC document `type`
(`sbom` / `sarif` / `attestation` / `vex` / `evidence`), the source
artifact path, the integrity hash, and the CVE list when populated.
Evidence types that GUAC does not have a native collector for fall
back to `type: "evidence"`.

## Loading into a local GUAC instance

GUAC runs as a small stack of services. Bring one up with the
project's compose file, then point the file collector at the
container:

```bash
# 1. Start a local GUAC stack (see https://docs.guac.sh for the
#    current quickstart — GUAC is pre-1.0, commands may evolve)
git clone https://github.com/guacsec/guac.git
cd guac
make container
make start-service

# 2. Ingest the collection produced above
guacone collect files /path/to/output/sample_release/guac-collection.json

# 3. Confirm the documents were stitched into the graph
guacone query known package "pkg:pypi/secure-sdlc-evidence-collector"
```

`guacone collect files` walks the container, reads each referenced
upstream document, and ingests it. The release envelope
(`application`, `repository`, `release_id`, `commit_sha`) keeps the
documents grouped so a graph query can scope to a single release.

## Querying

Once ingested, GUAC's GraphQL surface answers questions the bundle
alone cannot — because the graph spans every release you have loaded:

- "Which releases of this application shipped a SARIF SAST scan
  **and** an SBOM **and** an artifact attestation?"
- "Which bundles across the org contain `CVE-2026-XXXXX`?"
- "What is the most recent `ready` release of product X, and what
  evidence backed the verdict?"

GUAC's own docs cover the GraphQL schema and the `guacone query`
helpers: <https://docs.guac.sh>.

## Limitations

- **GUAC is pre-1.0.** The `guac-collect` container is intentionally
  minimal so it survives the next GUAC schema bump without a major
  rewrite. If GUAC's collector family changes how it reads upstream
  documents, a future ADR will bump the container `version`.
- **Adapter is one-way.** The collector emits a container *for*
  GUAC; it does not read a graph *back* from GUAC.
- **Continuous ingestion is deferred.** The `sdlc-evidence watch`
  daemon — webhook receiver that would emit GUAC collections on
  every release event — is deferred to v2.1. See
  [`limitations.md §17`](./limitations.md). For now, generate the
  container in the same CI job that produces the bundle and ingest
  it as a follow-up step.

## See also

- [ADR-0012 — GUAC graph integration](./adr/0012-guac-graph-integration.md)
- [Comparison vs alternatives](./comparison.md) — where the collector
  feeds GUAC rather than competing with it
- [GUAC documentation](https://docs.guac.sh)
- [GUAC on GitHub](https://github.com/guacsec/guac)
- [GUAC — OpenSSF project page](https://openssf.org/projects/guac/)
