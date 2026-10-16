# Loading bundles into GUAC

The Secure SDLC Evidence Collector ships a thin adapter that turns a
bundle into a `guac-collect` container — a single JSON index of the
documents behind a release, each labelled with its file format, so
the ones [GUAC](https://docs.guac.sh) can ingest (SBOMs and in-toto
attestations) can be picked out and fed to `guacone collect files`
without disassembling the bundle by hand. GUAC does not read the
container itself.

## Why

GUAC (Graph for Understanding Artifact Composition) is the OpenSSF
Incubating canonical graph backend for supply-chain metadata. It
ingests upstream documents — SBOMs, in-toto attestations, VEX — and
stitches them into a graph that answers cross-repository
questions: what depends on what, who built what, which CVEs affect
which artifacts.

A bundle already knows what each artifact is (its evidence type,
subject, integrity hash, CVE list). The GUAC adapter is a routing
layer: it emits one index of the whole release that says which file
is which format, so a script can select the ingestible ones. The decision and its
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

Each `documents[]` entry carries the document `type`
(`sbom` / `sarif` / `attestation` / `evidence`), the source
artifact path, the integrity hash, and
the CVE list when populated. `type` names the format of the file, not
the kind of evidence it supports:

- `sbom` — a CycloneDX or SPDX document.
- `sarif` — a SARIF log.
- `attestation` — an in-toto Statement, bare or inside a DSSE envelope
  or Sigstore bundle (SLSA provenance, VSA, release attestations, other
  in-toto predicates).
- `evidence` — anything else: tool-native JSON such as ZAP, Trivy or
  OSV-Scanner reports, package-registry attestation responses (a PyPI
  Integrity API provenance object, an npm or GitHub `attestations[]`
  list), the collector's own YAML/JSON attestations, JUnit XML, AI
  evaluation results. Registry responses wrap their statements in a
  shape GUAC does not read, so they are not `attestation`.

The collector does not ingest VEX documents, so the container never
lists one.

`artifact_path` is rewritten with forward slashes only when it is an
unambiguous Windows path: a drive-letter prefix (`C:\`) or a UNC prefix
(`\\server\`). Every other path, including a relative path that contains
backslashes such as `reports\scan.json`, is emitted exactly as the
collector recorded it, because a backslash is a valid character in a POSIX
filename. A bundle produced on Windows from relative paths therefore keeps
its backslashes; produce it with `--artifact-root` on the system that will
read the files, or convert the paths yourself.

## Loading into a local GUAC instance

GUAC runs as a small stack of services. GUAC's file collector reads
SBOMs, in-toto attestations, DSSE envelopes, OpenVEX, CSAF and
Scorecard documents; it does not read the `guac-collect` container
and has no SARIF processor. Use the container to select the
`sbom` and `attestation` documents and hand each file to
`guacone collect files`:

```bash
# 1. Start a local GUAC stack (see https://docs.guac.sh for the
#    current quickstart; commands may evolve between GUAC releases).
#    The subshell keeps your shell in the collection root.
git clone https://github.com/guacsec/guac.git
(cd guac && make container && make start-service)

# 2. Ingest the documents GUAC understands. artifact_path is the path the
#    collector read, made relative to --artifact-root when one was passed,
#    so run this from that root (or from where `sdlc-evidence run` ran),
#    not from inside the guac checkout.
#    The paths are NUL-delimited (jq 1.7+ --raw-output0) so names with spaces
#    or newlines reach guacone unchanged.
jq --raw-output0 '.documents[] | select(.type == "sbom" or .type == "attestation") | .artifact_path | strings' \
  output/sample_release/guac-collection.json \
  | sort -zu \
  | while IFS= read -r -d '' path; do guacone collect files "$path"; done

# 3. Confirm the documents were stitched into the graph
guacone query known package "pkg:pypi/secure-sdlc-evidence-collector"
```

The release envelope (`application`, `repository`, `release_id`,
`commit_sha`) records which release the documents belong to; GUAC
itself does not see it, because it ingests the files one by one.

## Querying

GUAC only receives the SBOM and attestation files the loop above hands
it. It never sees the release envelope, the SARIF and tool-native
reports, the bundle's CVE records or its `release_status`, so it cannot
answer release-level questions such as which releases shipped a SAST
scan or which release was last `ready`; those stay in the bundles.

What the graph can answer is what GUAC builds from SBOMs and
attestations across everything you have loaded, for example which
packages and versions appear in your SBOMs, which artifacts have an
attestation, and which known vulnerabilities GUAC associates with those
packages.

GUAC's own docs cover the GraphQL schema and the `guacone query`
helpers: <https://docs.guac.sh>.

## Limitations

- **GUAC does not read the container.** It is an index for your own
  ingestion script; only the `sbom` and `attestation` documents it
  lists are formats GUAC ingests. SARIF and tool-native JSON reports
  stay out of the graph.
- **No end-to-end GUAC test.** Ingestion against a running GUAC stack
  is not exercised in CI.
- **The container format may evolve.** It is intentionally minimal so
  it survives a GUAC schema change without a major rewrite. If the
  shape changes, a future ADR will bump the container `version`.
- **Adapter is one-way.** The collector emits a container *for*
  GUAC; it does not read a graph *back* from GUAC.
- **Continuous ingestion is deferred.** The `sdlc-evidence watch`
  daemon — webhook receiver that would emit GUAC collections on
  every release event — was planned for v2.1 and is not scheduled. See
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
