"""Shared helpers for parsers.

The public API of this module is stable across parsers so normalizers can
build NormalizedEvidence consistently without knowing the source format.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

MAX_INPUT_BYTES = 25 * 1024 * 1024  # 25 MB; protects against accidental huge inputs


class ParseError(ValueError):
    """Raised when a raw evidence file cannot be parsed into our schema."""


@dataclass(frozen=True)
class ParsedArtifact:
    """A minimal, parser-friendly view of an on-disk evidence artifact."""

    path: Path
    content_type: str
    size_bytes: int
    integrity_hash: str


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    """Return `<algorithm>:<hex-digest>` for the file at `path`."""
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return f"{algorithm}:{hasher.hexdigest()}"


def ensure_file(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise FileNotFoundError(f"File not found: {candidate}")
    size = candidate.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ParseError(
            f"File {candidate} is {size} bytes, exceeding the {MAX_INPUT_BYTES} byte safety cap."
        )
    return candidate


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"Expected top-level JSON object in {path}, got {type(data).__name__}")
    return data


def load_yaml_or_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ParseError(f"Invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(
            f"Expected top-level mapping in {path}, got {type(data).__name__ if data else 'empty'}"
        )
    return data


def describe(path: Path, content_type: str) -> ParsedArtifact:
    return ParsedArtifact(
        path=path,
        content_type=content_type,
        size_bytes=path.stat().st_size,
        integrity_hash=hash_file(path),
    )
