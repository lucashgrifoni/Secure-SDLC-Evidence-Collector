"""in-toto release-attestation parser.

GitHub's immutable releases (GA 2025-10-28) publish a Sigstore bundle whose
in-toto Statement carries the **release** predicate. Where SLSA provenance
states *how* an artifact was built, a release attestation states *what was
released*: a package URL identifying the released name and version, and the
set of assets — each with its digest — that make up that release. That
binding is release evidence in its own right, and it is what lets a reviewer
tell "these files are the v2.1.0 release" from "these files were on a runner".

Two predicate versions coexist and both are accepted::

    https://in-toto.io/attestation/release/v0.1
    https://in-toto.io/attestation/release/v0.2

in-toto v1.2.0 renamed the ``releaseId`` predicate field to ``packageId``;
this parser reads either and surfaces it as ``package_id``. Per the spec,
``purl`` is the only **required** predicate field — an attestation without it
is rejected rather than normalized, so a shapeless attestation can never make
a release-integrity control look met.

The released assets are **not** in the predicate: they are the Statement's
``subject`` entries, each with a ``name`` (the filename as it appears on
disk) and a ``digest`` object. This parser reads them from there.

Envelope handling — raw Statement, DSSE, Sigstore bundle, and the JSONL that
``gh attestation download`` writes — is shared with the other in-toto
predicate parsers via :mod:`evidence_collector.parsers._intoto`.

Consistent with the project's scope (see ``docs/limitations.md``): the
collector decodes and records the *stated* release. It does **not** verify
the DSSE signature or the Sigstore material.
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

# Exact strings, not a prefix: only the two vetted versions are understood.
# A future ``/v0.3`` must fail loudly rather than be parsed under v0.2
# assumptions, because the v0.1 -> v0.2 change was itself a field rename.
RELEASE_PREDICATE_TYPES = frozenset(
    {
        "https://in-toto.io/attestation/release/v0.1",
        "https://in-toto.io/attestation/release/v0.2",
    }
)


@dataclass(frozen=True)
class ReleaseAsset:
    """One released file: its name and whatever digests were stated for it."""

    name: str
    digests: dict[str, str]


@dataclass
class ParsedReleaseAttestation:
    artifact: ParsedArtifact
    predicate_type: str
    purl: str
    envelope: str
    package_id: str | None = None
    subject_name: str | None = None
    assets: list[ReleaseAsset] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _is_release_predicate(predicate_type: str) -> bool:
    return predicate_type in RELEASE_PREDICATE_TYPES


def file_has_release_attestation(path: Path) -> bool:
    """True when ``path`` holds at least one release attestation (a single
    JSON object, or any record of a JSONL). Used by the local collector for
    detection; never raises on an unreadable file."""
    return file_has_statement(path, _is_release_predicate)


def _digests(entry: dict[str, Any]) -> dict[str, str]:
    """Return the stated ``digest`` map, keeping only string values.

    A non-string digest is dropped rather than coerced: carrying a malformed
    hash into the evidence would make it look like a real binding.
    """
    digest = entry.get("digest")
    if not isinstance(digest, dict):
        return {}
    return {
        algorithm: value
        for algorithm, value in digest.items()
        if isinstance(algorithm, str) and isinstance(value, str) and value
    }


def _assets(statement: dict[str, Any]) -> list[ReleaseAsset]:
    """Collect the released files from the Statement ``subject`` array.

    Entries without a usable ``name`` are skipped; an asset stated without a
    digest is still recorded, because its presence in the release is itself
    the claim being made.
    """
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return []
    assets: list[ReleaseAsset] = []
    for entry in subjects:
        if not isinstance(entry, dict):
            continue
        name = _optional_str(entry.get("name"))
        if name is None:
            continue
        assets.append(ReleaseAsset(name=name, digests=_digests(entry)))
    return assets


def parse_release_attestation(path: str | Path) -> ParsedReleaseAttestation:
    resolved = ensure_file(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Invalid text encoding in {resolved}: {exc}") from exc

    records = iter_record_dicts(text)
    if not records:
        raise ParseError(f"File {resolved} is not a JSON object or a JSONL of objects.")

    found = find_statement(records, _is_release_predicate)
    if found is None:
        raise ParseError(
            f"File {resolved} contains no in-toto release attestation (a predicateType "
            f"among {sorted(RELEASE_PREDICATE_TYPES)}) across {len(records)} record(s)."
        )
    record, statement, envelope = found
    predicate_type = statement["predicateType"]

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ParseError(f"Release attestation {resolved} is missing a 'predicate' object.")

    # The only field the spec marks required. Without it the attestation
    # identifies no release, so it must not satisfy a release-integrity control.
    purl = _optional_str(predicate.get("purl"))
    if purl is None:
        raise ParseError(f"Release attestation {resolved} is missing required field 'purl'.")

    # v0.2 name first, v0.1 name as the fallback.
    package_id = _optional_str(predicate.get("packageId")) or _optional_str(
        predicate.get("releaseId")
    )

    artifact = describe(resolved, content_type="application/json")
    return ParsedReleaseAttestation(
        artifact=artifact,
        predicate_type=predicate_type,
        purl=purl,
        envelope=envelope,
        package_id=package_id,
        subject_name=first_subject_name(statement),
        assets=_assets(statement),
        raw=record,
    )
