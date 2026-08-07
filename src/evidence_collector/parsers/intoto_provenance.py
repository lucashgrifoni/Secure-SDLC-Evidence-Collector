"""SLSA build-provenance parser (incl. GitHub Artifact Attestations).

GitHub Artifact Attestations (``actions/attest-build-provenance`` /
``gh attestation``), npm/PyPI provenance, and SLSA generic-generator output
all express **build provenance** as an in-toto Statement carrying the SLSA
Provenance predicate (``https://slsa.dev/provenance/v1`` or ``…/v0.2``). The
statement states *how* an artifact was built — builder identity, build type,
and the materials consumed — which is exactly the kind of release evidence the
collector normalizes (distinct from *verifying* the signature).

The envelopes these attestations travel in — raw in-toto Statement, DSSE,
Sigstore bundle, and the JSONL that ``gh attestation download`` writes — are
handled by :mod:`evidence_collector.parsers._intoto`, which every in-toto
predicate parser shares. This module contributes only the part that is
specific to SLSA provenance: which ``predicateType`` to look for, and how to
read builder identity and build type out of the predicate.

Consistent with the project's scope (see ``docs/limitations.md``): the
collector decodes and records the *stated* provenance. It does **not** verify
the DSSE signature or the Sigstore material — that is an upstream concern.
Provenance missing the required ``builder.id`` or ``buildType`` is rejected so
an anonymous attestation cannot make a build-integrity control look met.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
)
from evidence_collector.parsers._intoto import (
    file_has_statement,
    find_statement,
    first_subject_name,
    iter_record_dicts,
)

SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/"


def _is_provenance_predicate(predicate_type: str) -> bool:
    """SLSA provenance is versioned in the path (``…/provenance/v1``,
    ``…/v0.2``), so the prefix — not an exact string — is the marker."""
    return predicate_type.startswith(SLSA_PROVENANCE_PREFIX)


@dataclass
class ParsedProvenance:
    artifact: ParsedArtifact
    predicate_type: str
    builder_id: str
    build_type: str
    envelope: str
    subject_name: str | None = None
    invocation_id: str | None = None
    source_repository: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def file_has_provenance(path: Path) -> bool:
    """True when ``path`` holds at least one SLSA provenance record (a single
    JSON object, or any record of a JSONL). Used by the local collector for
    detection; never raises on an unreadable file."""
    return file_has_statement(path, _is_provenance_predicate)


def _builder_id(predicate: dict[str, Any]) -> str | None:
    run_details = predicate.get("runDetails")  # SLSA Provenance v1
    if isinstance(run_details, dict):
        builder = run_details.get("builder")
        if isinstance(builder, dict):
            builder_id = _optional_str(builder.get("id"))
            if builder_id is not None:
                return builder_id
    builder = predicate.get("builder")  # SLSA Provenance v0.2
    if isinstance(builder, dict):
        return _optional_str(builder.get("id"))
    return None


def _build_type(predicate: dict[str, Any]) -> str | None:
    build_definition = predicate.get("buildDefinition")  # v1
    if isinstance(build_definition, dict):
        build_type = _optional_str(build_definition.get("buildType"))
        if build_type is not None:
            return build_type
    return _optional_str(predicate.get("buildType"))  # v0.2


def _invocation_id(predicate: dict[str, Any]) -> str | None:
    run_details = predicate.get("runDetails")
    if isinstance(run_details, dict):
        metadata = run_details.get("metadata")
        if isinstance(metadata, dict):
            invocation_id = _optional_str(metadata.get("invocationId"))
            if invocation_id is not None:
                return invocation_id
    metadata = predicate.get("metadata")
    if isinstance(metadata, dict):
        return _optional_str(metadata.get("invocationId"))
    return None


def _source_repository(predicate: dict[str, Any]) -> str | None:
    build_definition = predicate.get("buildDefinition")
    if not isinstance(build_definition, dict):
        return None
    external = build_definition.get("externalParameters")
    if not isinstance(external, dict):
        return None
    workflow = external.get("workflow")
    if isinstance(workflow, dict):
        return _optional_str(workflow.get("repository"))
    return None


def parse_provenance(path: str | Path) -> ParsedProvenance:
    resolved = ensure_file(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Invalid text encoding in {resolved}: {exc}") from exc
    records = iter_record_dicts(text)
    if not records:
        raise ParseError(f"File {resolved} is not a JSON object or a JSONL of objects.")

    found = find_statement(records, _is_provenance_predicate)
    if found is None:
        raise ParseError(
            f"File {resolved} contains no SLSA provenance (a predicateType under "
            f"'{SLSA_PROVENANCE_PREFIX}') across {len(records)} record(s)."
        )
    record, statement, envelope = found
    predicate_type = statement["predicateType"]

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ParseError(f"Provenance {resolved} is missing a 'predicate' object.")

    # Required so an anonymous / shapeless provenance cannot satisfy a control.
    builder_id = _builder_id(predicate)
    if builder_id is None:
        raise ParseError(f"Provenance {resolved} is missing required field 'builder.id'.")

    build_type = _build_type(predicate)
    if build_type is None:
        raise ParseError(f"Provenance {resolved} is missing required field 'buildType'.")

    artifact = describe(resolved, content_type="application/json")
    return ParsedProvenance(
        artifact=artifact,
        predicate_type=predicate_type,
        builder_id=builder_id,
        build_type=build_type,
        envelope=envelope,
        subject_name=first_subject_name(statement),
        invocation_id=_invocation_id(predicate),
        source_repository=_source_repository(predicate),
        raw=record,
    )
