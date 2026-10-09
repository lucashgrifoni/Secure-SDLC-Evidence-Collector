"""Shared helpers for parsers.

The public API of this module is stable across parsers so normalizers can
build NormalizedEvidence consistently without knowing the source format.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

import yaml

MAX_INPUT_BYTES = 25 * 1024 * 1024  # 25 MB; protects against accidental huge inputs

#: How much a YAML document may grow when its aliases are expanded, measured in
#: nodes plus scalar characters beyond what the document holds without them.
#: Ordinary anchors (shared defaults, a merge key reused per environment) add a
#: few hundred units; the classic billion-laughs file adds ten per level and
#: passes the limit at six levels while still under a kilobyte on disk.
MAX_YAML_ALIAS_EXPANSION = 1_000_000


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
        with path.open("r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ParseError(f"Invalid JSON in {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        # A UTF-16 SARIF (what `scanner > report.json` writes on Windows
        # PowerShell) or any non-UTF-8 byte would otherwise escape as a raw
        # UnicodeDecodeError and abort the whole collection run.
        raise ParseError(f"Invalid text encoding in {path}: {exc}") from exc
    except RecursionError as exc:
        # `json.load` recurses per nesting level, so a deeply nested document
        # blows the interpreter's stack. RecursionError is not an OSError and
        # not a ParseError, so it escaped the collector's guard and took the
        # entire run with it — every sibling artifact discarded because one
        # file was malformed.
        raise ParseError(f"JSON in {path} is nested too deeply to parse") from exc
    except ValueError as exc:
        # CPython caps int(str) at 4300 digits (CVE-2020-10735), and `json.load`
        # raises a bare ValueError — not a JSONDecodeError — for a longer
        # numeric literal. Same escape, same blast radius.
        raise ParseError(f"Invalid JSON value in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(f"Expected top-level JSON object in {path}, got {type(data).__name__}")
    return data


class YamlAliasExpansionError(yaml.YAMLError):
    """A YAML document whose aliases expand far beyond its size on disk."""


def _yaml_children(node: yaml.Node) -> list[yaml.Node]:
    if isinstance(node, yaml.SequenceNode):
        return list(node.value)
    if isinstance(node, yaml.MappingNode):
        return [part for pair in node.value for part in pair]
    return []


def _check_alias_expansion(root: yaml.Node) -> None:
    """Refuse a composed document whose aliases expand past the budget.

    `yaml.safe_load` resolves an alias to the very node its anchor names, so
    loading shares references and costs nothing. The cost lands downstream:
    attestation metadata is copied verbatim into the evidence record, and
    serializing the bundle writes every alias out in full. `MAX_INPUT_BYTES`
    only measures the file on disk, so a 421-byte billion-laughs attestation
    became a 34.6 MB bundle at six levels, and ~35 GB at nine.

    The check weighs the document twice over the composed node graph — once
    counting each node a single time, once with every alias expanded in place
    (memoized, so it stays linear in the number of distinct nodes) — and fails
    when the difference exceeds `MAX_YAML_ALIAS_EXPANSION`. Scalars weigh their
    length, so one large anchored string referenced many times counts too. A
    recursive alias expands without end and is refused outright.
    """
    expanded: dict[int, int] = {}
    on_path: set[int] = set()
    distinct = 0
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, children_done = stack.pop()
        key = id(node)
        if children_done:
            on_path.discard(key)
            expanded[key] = 1 + sum(expanded[id(child)] for child in _yaml_children(node))
            continue
        if key in expanded:
            continue
        if key in on_path:
            raise YamlAliasExpansionError(
                "the document contains a recursive alias (an anchor that refers to itself)"
            )
        if isinstance(node, yaml.ScalarNode):
            weight = max(1, len(str(node.value)))
            distinct += weight
            expanded[key] = weight
            continue
        distinct += 1
        on_path.add(key)
        stack.append((node, True))
        stack.extend((child, False) for child in _yaml_children(node))
    growth = expanded[id(root)] - distinct
    if growth > MAX_YAML_ALIAS_EXPANSION:
        raise YamlAliasExpansionError(
            f"alias expansion would grow the document by {growth} units, past the "
            f"{MAX_YAML_ALIAS_EXPANSION} limit (a YAML alias bomb?)"
        )


class _AliasBoundedSafeLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` that refuses documents whose aliases explode."""

    def compose_document(self) -> yaml.Node | None:
        node: yaml.Node | None = super().compose_document()
        if node is not None:
            _check_alias_expansion(node)
        return node


def safe_load_yaml(stream: str | bytes | IO[str] | IO[bytes]) -> Any:
    """`yaml.safe_load` with a bound on alias expansion.

    Every YAML read from operator-supplied input goes through here, so the
    alias bound cannot be skipped by one call site. Raises `yaml.YAMLError`
    (`YamlAliasExpansionError` for the bound), like `yaml.safe_load`.
    """
    return yaml.load(stream, Loader=_AliasBoundedSafeLoader)  # noqa: S506 - SafeLoader subclass


def load_yaml_or_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            data = safe_load_yaml(handle)
    except yaml.YAMLError as exc:
        raise ParseError(f"Invalid YAML in {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ParseError(f"Invalid text encoding in {path}: {exc}") from exc
    except RecursionError as exc:
        raise ParseError(f"YAML in {path} is nested too deeply to parse") from exc
    except ValueError as exc:
        # SafeLoader builds datetimes and ints itself, and an impossible value
        # (`24:00`, April 31, a `+25:00` offset, an int past CPython's
        # 4300-digit cap) raises a bare ValueError from the constructor rather
        # than a YAMLError. Same escape as in `load_json`, same treatment.
        raise ParseError(f"Invalid YAML value in {path}: {exc}") from exc
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
