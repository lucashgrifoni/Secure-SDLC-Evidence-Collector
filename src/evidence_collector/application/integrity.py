"""Structural integrity helpers for bundle.json.

The collector promises that running the same pipeline against the same
inputs produces the same bundle once a small set of volatile fields
(``bundle_id``, ``generated_at``, per-evidence ``collected_at``, per-
control ``evaluated_at``) is removed. This module exposes that
"normalize then SHA-256" computation as a public surface so both the CI
determinism gates and the ``sdlc-evidence verify`` command share one
canonical implementation.

A new top-level or nested key counts as volatile only when it varies
across runs that should be considered structurally equivalent. Anything
else MUST be part of the hash so drift is surfaced.

Cross-OS note: ``evidence[*].raw[*].artifact_path`` carries the host's
native path separator (``\\`` on Windows, ``/`` on POSIX). The collector
should record what the runtime saw, but the structural hash must agree
across operating systems — otherwise a CI matrix that builds the same
inputs on Linux and Windows would always report drift. We therefore
POSIX-normalize ``artifact_path`` (and ``artifact_uri`` when it is a
relative ``file://``-style path) only at hash time; the bundle written
to disk is untouched.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final

VOLATILE_TOP: Final[frozenset[str]] = frozenset({"bundle_id", "generated_at"})
VOLATILE_EVIDENCE: Final[frozenset[str]] = frozenset({"collected_at"})
VOLATILE_CONTROL: Final[frozenset[str]] = frozenset({"evaluated_at"})

# Keys inside each entry of evidence[*].raw[*] whose value is a filesystem
# path and must be normalized to POSIX form before hashing.
PATH_KEYS_IN_RAW: Final[frozenset[str]] = frozenset({"artifact_path"})


def _to_posix(value: object) -> object:
    """Return ``value`` with Windows separators flipped to ``/``.

    Non-string values pass through. ``None`` passes through. We do not
    touch absolute paths or URIs that already use forward slashes — the
    replacement is a no-op in that case.
    """
    if isinstance(value, str):
        return value.replace("\\", "/")
    return value


def _normalize_raw_paths(entry: dict[str, object]) -> None:
    """In-place POSIX-normalize path-bearing keys inside one evidence dict.

    ``raw`` is serialized as either a single dict (current ``RawEvidenceRef``
    shape) or a list of such dicts (for future schemas that may carry
    multiple raw refs per evidence entry). Both are supported so the hash
    helper does not need a schema migration to stay correct.
    """
    raw = entry.get("raw")
    refs: list[dict[str, object]]
    if isinstance(raw, dict):
        refs = [raw]
    elif isinstance(raw, list):
        refs = [r for r in raw if isinstance(r, dict)]
    else:
        return
    for ref in refs:
        for key in PATH_KEYS_IN_RAW:
            if key in ref:
                ref[key] = _to_posix(ref[key])


def _strip_keys(entries: object, keys: frozenset[str]) -> list[dict[str, object]]:
    """Drop ``keys`` from every dict in ``entries`` (no-op on non-lists)."""
    if not isinstance(entries, list):
        return []
    dict_entries = [e for e in entries if isinstance(e, dict)]
    for entry in dict_entries:
        for key in keys:
            entry.pop(key, None)
    return dict_entries


def normalize_bundle(data: dict[str, object]) -> bytes:
    """Strip volatile fields and return a canonical UTF-8 JSON byte stream.

    The input is mutated in place because callers always pass a freshly
    loaded dict; if a future use case needs an immutable copy, switch to
    ``copy.deepcopy(data)`` at the entry of this function.
    """
    for key in VOLATILE_TOP:
        data.pop(key, None)
    for entry in _strip_keys(data.get("evidence"), VOLATILE_EVIDENCE):
        _normalize_raw_paths(entry)
    _strip_keys(data.get("control_evaluations"), VOLATILE_CONTROL)
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")


def structural_sha256(bundle_path: Path) -> str:
    """Return the structural SHA-256 of a bundle JSON file."""
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    return hashlib.sha256(normalize_bundle(data)).hexdigest()
