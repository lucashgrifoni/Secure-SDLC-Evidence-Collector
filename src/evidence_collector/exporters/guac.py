"""GUAC (Graph for Understanding Artifact Composition) adapter. T6.9.

GUAC (https://docs.guac.sh) ingests supply-chain documents (SBOMs,
in-toto attestations, VEX, ...) and stitches them into a graph. Its
native ingest format is **the document itself**. This adapter emits
a single JSON index of the documents a bundle carries, so a consumer
can pick out the ones GUAC can ingest and feed each to ``guacone
collect files``. GUAC does not read the index itself.

Schema
------

    {
      "format": "guac-collect",
      "version": "1.0",
      "source": "secure-sdlc-evidence-collector",
      "release": {
        "application": "...",
        "repository": "...",
        "release_id": "...",
        "commit_sha": "..."
      },
      "documents": [
        {
          "type": "sbom" | "sarif" | "attestation" | "evidence",
          "evidence_id": "...",
          "evidence_type": "<canonical EvidenceType>",
          "subject": {"type": "<SubjectType>", "ref": "..."},
          "artifact_path": "<POSIX path>",
          "integrity_hash": "sha256:..."
        },
        ...
      ]
    }

``type`` names the format of the file at ``artifact_path``, not the
kind of evidence it supports: a ZAP, Trivy or OSV-Scanner JSON report
is ``evidence``, not ``sarif``, because it is not SARIF. The container
is intentionally minimal so it survives a GUAC schema change without
a rewrite on our side.
"""

from __future__ import annotations

from typing import Any

from evidence_collector.domain.models import EvidenceBundle, NormalizedEvidence

# Every value `type` can take, in the order the docs list them.
GUAC_DOCUMENT_TYPES: tuple[str, ...] = ("sbom", "sarif", "attestation", "evidence")

# The source kinds whose file is an in-toto Statement, bare or wrapped in a
# DSSE envelope or a Sigstore bundle. `attestation` (no prefix) is the
# collector's own YAML/JSON attestation format, which is not in-toto.
_INTOTO_SOURCE_KINDS = frozenset(
    {"slsa-provenance", "slsa-vsa", "release-attestation", "registry-attestation"}
)


def _document_type_for(evidence: NormalizedEvidence) -> str:
    """Label a document by the format of its file.

    The label used to follow the evidence type, so every scan was "sarif"
    and every attestation "attestation": a ZAP, Trivy or OSV-Scanner JSON
    report was announced as SARIF and the collector's own YAML attestation
    as in-toto. A consumer dispatching on `type` handed them to the wrong
    parser. The parser that read the file knows its format, recorded in
    `source.kind` and `raw.content_type`.
    """
    kind = evidence.source.kind
    content_type = (evidence.raw.content_type if evidence.raw else None) or ""
    if kind == "sbom" or content_type in {
        "application/vnd.cyclonedx+json",
        "application/spdx+json",
    }:
        return "sbom"
    if kind == "sarif" or content_type == "application/sarif+json":
        return "sarif"
    if kind in _INTOTO_SOURCE_KINDS or kind.startswith("in-toto-"):
        return "attestation"
    return "evidence"


def _document_entry(evidence: NormalizedEvidence) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": _document_type_for(evidence),
        "evidence_id": evidence.evidence_id,
        "evidence_type": evidence.evidence_type.value,
        "subject": {
            "type": evidence.subject_type.value,
            "ref": evidence.subject_ref,
        },
        "status": evidence.status.value,
        "producer": evidence.producer,
    }
    if evidence.raw is not None:
        if evidence.raw.artifact_path:
            # A Windows run records backslashes; the container is consumed
            # by POSIX tooling, so it carries forward slashes everywhere.
            entry["artifact_path"] = evidence.raw.artifact_path.replace("\\", "/")
        if evidence.raw.integrity_hash:
            entry["integrity_hash"] = evidence.raw.integrity_hash
    if evidence.cve_ids:
        entry["cve_ids"] = list(evidence.cve_ids)
    return entry


def build_guac_collection(bundle: EvidenceBundle) -> dict[str, Any]:
    """Return a GUAC-collector-shaped JSON dict for ``bundle``.

    The result is plain JSON-serialisable so the CLI can write it
    with ``json.dumps``; no Pydantic round-trip is required.
    """
    return {
        "format": "guac-collect",
        "version": "1.0",
        "source": "secure-sdlc-evidence-collector",
        "release": {
            "application": bundle.application.name,
            "repository": bundle.application.repository,
            "release_id": bundle.release.release_id,
            "commit_sha": bundle.release.commit_sha,
        },
        "documents": [_document_entry(e) for e in bundle.evidence],
    }
