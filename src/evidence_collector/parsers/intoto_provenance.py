"""SLSA build-provenance parser (incl. GitHub Artifact Attestations).

GitHub Artifact Attestations (``actions/attest-build-provenance`` /
``gh attestation``), npm/PyPI provenance, and SLSA generic-generator output
all express **build provenance** as an in-toto Statement carrying the SLSA
Provenance predicate (``https://slsa.dev/provenance/v1`` or ``…/v0.2``). The
statement states *how* an artifact was built — builder identity, build type,
and the materials consumed — which is exactly the kind of release evidence the
collector normalizes (distinct from *verifying* the signature).

This parser accepts the three shapes these attestations travel in:

* **raw in-toto Statement** — ``{"_type": ".../Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1", "predicate": {…}}``;
* **DSSE envelope** — ``{"payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 Statement>", "signatures": [...]}``;
* **Sigstore bundle** — ``{"mediaType": ".../bundle…", "dsseEnvelope":
  {"payload": "<base64>", …}, "verificationMaterial": {…}}`` (one per line in
  the ``.jsonl`` that ``gh attestation download`` writes; the first record is
  used).

Consistent with the project's scope (see ``docs/limitations.md``): the
collector decodes and records the *stated* provenance. It does **not** verify
the DSSE signature or the Sigstore material — that is an upstream concern.
Provenance missing the required ``builder.id`` or ``buildType`` is rejected so
an anonymous attestation cannot make a build-integrity control look met.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
)

SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/"


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


def _first_subject_name(statement: dict[str, Any]) -> str | None:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return None
    for entry in subjects:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def _decode_dsse(envelope: dict[str, Any]) -> dict[str, Any] | None:
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return None
    try:
        decoded = base64.b64decode(payload, validate=True)
        obj = json.loads(decoded)
    except (binascii.Error, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def _unwrap(data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return ``(in-toto Statement, envelope-kind)`` from any supported shape."""
    bundle_envelope = data.get("dsseEnvelope")
    if isinstance(bundle_envelope, dict):
        return _decode_dsse(bundle_envelope), "sigstore-bundle"
    if isinstance(data.get("payload"), str) and "payloadType" in data:
        return _decode_dsse(data), "dsse"
    if "predicateType" in data:
        return data, "statement"
    return None, "unknown"


def is_provenance_payload(data: dict[str, Any]) -> bool:
    """True when ``data`` unwraps to an in-toto Statement with a SLSA
    Provenance predicateType. Used by the local collector for detection."""
    statement, _ = _unwrap(data)
    if statement is None:
        return False
    predicate_type = statement.get("predicateType")
    return isinstance(predicate_type, str) and predicate_type.startswith(SLSA_PROVENANCE_PREFIX)


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


def _load_attestation(path: Path) -> dict[str, Any]:
    """Load a single JSON object, or the first record of a ``.jsonl`` file."""
    text = path.read_text(encoding="utf-8")
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None
    if isinstance(whole, dict):
        return whole
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            return candidate
    raise ParseError(f"File {path} is not a JSON object or a JSONL of objects.")


def parse_provenance(path: str | Path) -> ParsedProvenance:
    resolved = ensure_file(path)
    data = _load_attestation(resolved)

    statement, envelope = _unwrap(data)
    if statement is None:
        raise ParseError(
            f"File {resolved} is not a recognized in-toto attestation "
            "(raw Statement, DSSE envelope, or Sigstore bundle)."
        )

    predicate_type = statement.get("predicateType")
    if not (isinstance(predicate_type, str) and predicate_type.startswith(SLSA_PROVENANCE_PREFIX)):
        raise ParseError(
            f"File {resolved} is not SLSA provenance: expected a predicateType under "
            f"'{SLSA_PROVENANCE_PREFIX}', got '{predicate_type}'."
        )

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
        subject_name=_first_subject_name(statement),
        invocation_id=_invocation_id(predicate),
        source_repository=_source_repository(predicate),
        raw=data,
    )
