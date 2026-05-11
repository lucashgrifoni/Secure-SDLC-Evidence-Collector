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
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Final

VOLATILE_TOP: Final[frozenset[str]] = frozenset({"bundle_id", "generated_at"})
VOLATILE_EVIDENCE: Final[frozenset[str]] = frozenset({"collected_at"})
VOLATILE_CONTROL: Final[frozenset[str]] = frozenset({"evaluated_at"})


def normalize_bundle(data: dict[str, object]) -> bytes:
    """Strip volatile fields and return a canonical UTF-8 JSON byte stream.

    The input is mutated in place because callers always pass a freshly
    loaded dict; if a future use case needs an immutable copy, switch to
    ``copy.deepcopy(data)`` at the entry of this function.
    """
    for key in VOLATILE_TOP:
        data.pop(key, None)
    evidence = data.get("evidence")
    if isinstance(evidence, list):
        for entry in evidence:
            if isinstance(entry, dict):
                for key in VOLATILE_EVIDENCE:
                    entry.pop(key, None)
    controls = data.get("control_evaluations")
    if isinstance(controls, list):
        for entry in controls:
            if isinstance(entry, dict):
                for key in VOLATILE_CONTROL:
                    entry.pop(key, None)
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode("utf-8")


def structural_sha256(bundle_path: Path) -> str:
    """Return the structural SHA-256 of a bundle JSON file."""
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    return hashlib.sha256(normalize_bundle(data)).hexdigest()
