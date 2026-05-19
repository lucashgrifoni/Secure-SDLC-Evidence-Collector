"""Control catalog loader.

Loads the initial set of Secure SDLC controls the MVP evaluates. The default
catalog is shipped as YAML alongside the package and can be replaced or
extended by passing an alternative path.
"""

from __future__ import annotations

from functools import cache
from importlib.resources import as_file, files
from pathlib import Path
from typing import cast

import yaml
from pydantic import TypeAdapter

from evidence_collector.domain.models import ControlDefinition


def _coerce_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_file():
        raise FileNotFoundError(f"Control catalog not found at {candidate}")
    return candidate


def _parse_catalog(content: str, source: str) -> list[ControlDefinition]:
    try:
        raw = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in control catalog {source}: {exc}") from exc

    if not isinstance(raw, dict) or "controls" not in raw:
        raise ValueError(f"Control catalog {source} must contain a top-level 'controls' list")

    entries = raw["controls"]
    if not isinstance(entries, list):
        raise ValueError(f"Control catalog {source} 'controls' must be a list")

    adapter: TypeAdapter[list[ControlDefinition]] = TypeAdapter(list[ControlDefinition])
    controls = adapter.validate_python(entries)

    seen: set[str] = set()
    duplicates: list[str] = []
    for control in controls:
        if control.control_id in seen:
            duplicates.append(control.control_id)
        seen.add(control.control_id)
    if duplicates:
        raise ValueError(f"Control catalog {source} has duplicate control_id entries: {duplicates}")

    return controls


def load_catalog(path: str | Path) -> list[ControlDefinition]:
    """Load and validate a control catalog from the given filesystem path."""
    resolved = _coerce_path(path)
    content = resolved.read_text(encoding="utf-8")
    return _parse_catalog(content, str(resolved))


@cache
def default_catalog() -> list[ControlDefinition]:
    """Return the control catalog bundled with the package (cached)."""
    resource = files("evidence_collector.controls.data").joinpath("catalog.yaml")
    with as_file(resource) as path:
        content = Path(path).read_text(encoding="utf-8")
    return _parse_catalog(content, "packaged catalog.yaml")


def catalog_from_source(
    path: str | Path | None = None,
) -> list[ControlDefinition]:
    """Return the catalog at `path` or the packaged default when `path` is None."""
    if path is None:
        return cast("list[ControlDefinition]", list(default_catalog()))
    return load_catalog(path)


def bundled_catalog_path(name: str) -> Path:
    """Return the filesystem path of a YAML catalog shipped with the package.

    Lets callers pick a named catalog (``catalog-ssdf-1.2.yaml``) without
    hard-coding ``importlib.resources`` plumbing at every call site.
    Raises ``FileNotFoundError`` when the catalog is not bundled, which
    keeps the CLI failure mode aligned with ``load_catalog``.
    """
    resource = files("evidence_collector.controls.data").joinpath(name)
    with as_file(resource) as path:
        candidate = Path(path)
        if not candidate.is_file():
            raise FileNotFoundError(
                f"Bundled catalog '{name}' not found in evidence_collector.controls.data"
            )
        return candidate
