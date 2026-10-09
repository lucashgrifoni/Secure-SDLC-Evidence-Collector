"""Parser for manual attestations (YAML or JSON).

An attestation describes a Secure SDLC practice that is not produced by a
scanner or pipeline — typical examples are release approvals, threat model
references, rollback plans, or generic sign-offs.

Expected schema (YAML or JSON):

```yaml
evidence_type: release_approval  # any EvidenceType value
producer: "AppSec Lead"
subject_type: release
subject_ref: "payments-api:2026.04.10"
status: passed                   # optional; defaults to completed
confidence: medium               # optional; defaults to medium
generated_at: "2026-04-09T15:30:00Z"  # optional ISO 8601
approver: "alice@example.com"   # optional, stored in metadata
summary: "Release approved in change board 2026-04-09"
metadata:                        # optional, opaque payload
  change_ticket: CHG-1234
```
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
    load_yaml_or_json,
)


@dataclass
class ParsedAttestation:
    artifact: ParsedArtifact
    evidence_type: EvidenceType
    producer: str
    subject_type: SubjectType
    subject_ref: str
    status: EvidenceStatus
    confidence: ConfidenceLevel
    generated_at: datetime | None
    summary: str | None
    metadata: dict[str, Any] = field(default_factory=dict)


_REQUIRED = ("evidence_type", "producer", "subject_ref")


def _coerce_enum(enum_cls: type[Enum], value: Any, field_name: str, source: Path) -> Any:
    try:
        return enum_cls(value)
    except (ValueError, TypeError) as exc:
        allowed = ", ".join(str(member.value) for member in enum_cls)
        raise ParseError(
            f"Invalid {field_name} value in attestation {source}; expected one of: {allowed}"
        ) from exc


def _parse_datetime(value: Any, source: Path) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ParseError(
                f"Invalid ISO 8601 datetime in 'generated_at' in attestation {source}"
            ) from exc
    raise ParseError(
        f"Unsupported datetime value type {type(value).__name__} in attestation {source}"
    )


_JSON_SCALARS = (str, int, float, bool, type(None), date)


def _require_json_value(value: Any, key: str, source: Path) -> None:
    """Reject a value the bundle cannot serialize, naming the key it sits under.

    YAML can produce more than JSON can carry: `!!binary` yields bytes and
    `!!set` a set. Both were copied into the evidence metadata verbatim and
    only failed when the bundle was serialized, as a
    PydanticSerializationError that took the whole run down. YAML dates and
    timestamps are kept: they are native scalars the bundle already writes.
    YAML anchors can also build a container that contains itself, which JSON
    cannot represent, so a cycle is rejected instead of recursing forever.
    """
    try:
        _check_json_value(value, key, source, frozenset())
    except RecursionError as exc:
        raise ParseError(
            f"Value under '{key}' in attestation {source} is nested too deeply"
        ) from exc


def _check_json_value(value: Any, key: str, source: Path, ancestors: frozenset[int]) -> None:
    if isinstance(value, dict | list):
        if id(value) in ancestors:
            raise ParseError(
                f"Recursive YAML alias (a cycle) under '{key}' in attestation {source}; "
                "expected a JSON-compatible value"
            )
        inside = ancestors | {id(value)}
        if isinstance(value, dict):
            for inner_key, inner in value.items():
                _check_json_value(inner_key, key, source, inside)
                _check_json_value(inner, f"{key}.{inner_key}", source, inside)
        else:
            for inner in value:
                _check_json_value(inner, key, source, inside)
    elif not isinstance(value, _JSON_SCALARS):
        raise ParseError(
            f"Unsupported {type(value).__name__} value under '{key}' in attestation {source}; "
            "expected a JSON-compatible value"
        )


def parse_attestation(path: str | Path) -> ParsedAttestation:
    resolved = ensure_file(path)
    data = load_yaml_or_json(resolved)

    missing = [key for key in _REQUIRED if not data.get(key)]
    if missing:
        raise ParseError(f"Attestation {resolved} is missing required fields: {missing}")

    evidence_type = _coerce_enum(EvidenceType, data["evidence_type"], "evidence_type", resolved)
    subject_type_value = data.get("subject_type") or SubjectType.RELEASE.value
    subject_type = _coerce_enum(SubjectType, subject_type_value, "subject_type", resolved)
    status_value = data.get("status") or EvidenceStatus.COMPLETED.value
    status = _coerce_enum(EvidenceStatus, status_value, "status", resolved)
    confidence_value = data.get("confidence") or ConfidenceLevel.MEDIUM.value
    confidence = _coerce_enum(ConfidenceLevel, confidence_value, "confidence", resolved)
    generated_at = _parse_datetime(data.get("generated_at"), resolved)

    metadata: dict[str, Any] = {}
    raw_metadata = data.get("metadata")
    if isinstance(raw_metadata, dict):
        _require_json_value(raw_metadata, "metadata", resolved)
        metadata.update(raw_metadata)
    for optional_key in ("approver", "ticket", "change_ticket", "link"):
        if optional_key in data and optional_key not in metadata:
            _require_json_value(data[optional_key], optional_key, resolved)
            metadata[optional_key] = data[optional_key]

    summary = data.get("summary")
    if summary is not None and not isinstance(summary, str):
        summary = str(summary)

    if resolved.suffix.lower() in {".yaml", ".yml"}:
        content_type = "application/yaml"
    else:
        content_type = "application/json"
    artifact = describe(resolved, content_type=content_type)

    return ParsedAttestation(
        artifact=artifact,
        evidence_type=evidence_type,
        producer=str(data["producer"]),
        subject_type=subject_type,
        subject_ref=str(data["subject_ref"]),
        status=status,
        confidence=confidence,
        generated_at=generated_at,
        summary=summary,
        metadata=metadata,
    )
