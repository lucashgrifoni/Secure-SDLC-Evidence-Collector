"""Shared in-toto Statement plumbing.

Distinct attestation *predicates* — SLSA build provenance, the in-toto
release predicate, and anything else the collector learns to read — travel
in the same handful of envelopes. Each parser cares about a different
``predicate``, but every one of them first has to answer the same question:
*where is the in-toto Statement inside this file?*

The shapes a Statement arrives in:

* **raw in-toto Statement** — ``{"_type": ".../Statement/v1",
  "predicateType": "...", "predicate": {…}}``;
* **DSSE envelope** — ``{"payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 Statement>", "signatures": [...]}``;
* **Sigstore bundle** — ``{"mediaType": ".../bundle…", "dsseEnvelope":
  {"payload": "<base64>", …}, "verificationMaterial": {…}}``;
* **JSONL** — one record per line, as ``gh attestation download`` writes.
  A single download can hold several predicates (provenance, SBOM, release),
  so callers must scan every record rather than trusting the first one.

Consistent with the project's scope (see ``docs/limitations.md``): this
module decodes, it never verifies. The DSSE signature and the Sigstore
verification material are read past, not checked — that is an upstream
concern.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import MAX_INPUT_BYTES

# Given a ``predicateType`` string, decide whether this is the predicate the
# caller is looking for. Passed as a callable rather than a plain string so a
# parser can accept a family of versioned predicate types (``…/v0.1`` and
# ``…/v0.2``) without the shared code knowing the versioning rules.
PredicateMatcher = Callable[[str], bool]


def decode_dsse(envelope: dict[str, Any]) -> dict[str, Any] | None:
    """Return the Statement carried in a DSSE ``payload``, or None.

    The payload is base64 of the Statement JSON. A payload that is not valid
    base64, not valid JSON, or not a JSON object yields None rather than
    raising: the caller is usually scanning a multi-record file where one
    unreadable record must not abort the whole scan.
    """
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return None
    try:
        decoded = base64.b64decode(payload, validate=True)
        obj = json.loads(decoded)
    except (binascii.Error, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


def unwrap(data: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Return ``(in-toto Statement, envelope-kind)`` from any supported shape.

    ``envelope-kind`` is recorded on the normalized evidence so a reviewer can
    tell a bare Statement from one that arrived signed, without re-reading the
    artifact.
    """
    bundle_envelope = data.get("dsseEnvelope")
    if isinstance(bundle_envelope, dict):
        return decode_dsse(bundle_envelope), "sigstore-bundle"
    if isinstance(data.get("payload"), str) and "payloadType" in data:
        return decode_dsse(data), "dsse"
    if "predicateType" in data:
        return data, "statement"
    return None, "unknown"


def iter_record_dicts(text: str) -> list[dict[str, Any]]:
    """Return every JSON object in ``text`` — a single object, or each record
    of a JSONL document. Blank and non-JSON lines are skipped."""
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        whole = None
    if isinstance(whole, dict):
        return [whole]
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            candidate = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            records.append(candidate)
    return records


def find_statement(
    records: list[dict[str, Any]],
    matches: PredicateMatcher,
) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """Return ``(record, statement, envelope)`` for the first record whose
    unwrapped Statement carries a ``predicateType`` accepted by ``matches``.

    Scanning every record — rather than only the first — is what lets a
    ``gh attestation download`` JSONL holding several predicates yield the one
    the caller wants instead of whichever happens to appear first in the file.
    """
    for record in records:
        statement, envelope = unwrap(record)
        if statement is None:
            continue
        predicate_type = statement.get("predicateType")
        if isinstance(predicate_type, str) and matches(predicate_type):
            return record, statement, envelope
    return None


# One-slot memo keyed on (path, mtime, size), mirroring the collector's JSON
# peek. Detection asks the *same* file for one predicate after another —
# provenance, then release — and each question would otherwise re-read and
# re-deserialize the whole document. Keying on mtime and size means a file
# rewritten between two probes is never served a stale answer.
_LAST_RECORDS: dict[str, Any] = {"key": None, "value": None}


def _records_key(path: Path) -> tuple[str, int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (str(path), stat.st_mtime_ns, stat.st_size)


def read_records(path: Path) -> list[dict[str, Any]] | None:
    """Return every JSON object in ``path``, or None when it cannot be read.

    Applies the input cap directly. This runs during *detection*, ahead of any
    parser, and it reads the whole file rather than going through the
    collector's memoized peek (which parses one JSON document and so cannot
    represent a JSONL) — without the cap an oversized artifact would be fully
    loaded here even though every other detection path refuses it.

    Never raises: an unreadable or undecodable file is simply "not an in-toto
    attestation", and the parser that eventually claims it reports the real
    reason via ParseError.
    """
    key = _records_key(path)
    if key is None:
        return None
    if _LAST_RECORDS["key"] == key:
        records: list[dict[str, Any]] | None = _LAST_RECORDS["value"]
        return records

    value: list[dict[str, Any]] | None = None
    if key[2] <= MAX_INPUT_BYTES:
        try:
            value = iter_record_dicts(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            value = None
    _LAST_RECORDS["key"] = key
    _LAST_RECORDS["value"] = value
    return value


def file_has_statement(path: Path, matches: PredicateMatcher) -> bool:
    """True when ``path`` holds at least one Statement whose predicateType is
    accepted by ``matches``. Used by the local collector for detection; never
    raises on an unreadable file."""
    records = read_records(path)
    if records is None:
        return False
    return find_statement(records, matches) is not None


def first_subject_name(statement: dict[str, Any]) -> str | None:
    """Return the first non-empty ``subject[*].name``, or None."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return None
    for entry in subjects:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                return name
    return None
