"""GUAC (Graph for Understanding Artifact Composition) adapter. T6.9.

GUAC (https://docs.guac.sh) ingests supply-chain metadata as JSON
documents and stitches them into a graph. The native ingest format
is **the document itself** (an SBOM, a SARIF run, an attestation,
…); GUAC's ``collector/`` family knows how to read each shape. The
adapter here speaks the same dialect: it emits a single JSON
container with one entry per upstream document the bundle carries,
so ``guacone collect files`` can ingest the entire release in one
shot without the consumer having to disassemble the bundle first.

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
          "type": "sbom" | "sarif" | "attestation" | "vex" | "evidence",
          "evidence_id": "...",
          "evidence_type": "<canonical EvidenceType>",
          "subject": {"type": "<SubjectType>", "ref": "..."},
          "artifact_path": "...",
          "integrity_hash": "sha256:..."
        },
        ...
      ]
    }

GUAC's API is still pre-1.0 at the time of writing; the container
format here is intentionally minimal so the JSON survives the next
GUAC schema bump without a major rewrite on our side.
"""

from __future__ import annotations

from typing import Any

from evidence_collector.domain.enums import EvidenceType
from evidence_collector.domain.models import EvidenceBundle, NormalizedEvidence

_EVIDENCE_TYPE_TO_GUAC_DOCUMENT_TYPE: dict[EvidenceType, str] = {
    EvidenceType.SBOM: "sbom",
    EvidenceType.SAST_SCAN: "sarif",
    EvidenceType.SCA_SCAN: "sarif",
    EvidenceType.SECRETS_SCAN: "sarif",
    EvidenceType.DAST_SCAN: "sarif",
    EvidenceType.ARTIFACT_ATTESTATION: "attestation",
    EvidenceType.ARTIFACT_SIGNATURE: "attestation",
    EvidenceType.GENERIC_ATTESTATION: "attestation",
}


def _document_type_for(evidence: NormalizedEvidence) -> str:
    mapped = _EVIDENCE_TYPE_TO_GUAC_DOCUMENT_TYPE.get(evidence.evidence_type)
    if mapped is not None:
        return mapped
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
            entry["artifact_path"] = evidence.raw.artifact_path
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
