"""Control catalog loader.

Loads the initial set of Secure SDLC controls the MVP evaluates. The default
catalog is shipped as YAML alongside the package and can be replaced or
extended by passing an alternative path.
"""

from __future__ import annotations

import contextlib
import logging
from functools import cache
from importlib.resources import as_file, files
from pathlib import Path
from typing import cast

import yaml
from pydantic import TypeAdapter

from evidence_collector.domain.models import ControlDefinition


def bundled_catalog_names() -> list[str]:
    """Return the sorted names of every catalog shipped with the package."""
    return sorted(
        entry.name
        for entry in files("evidence_collector.controls.data").iterdir()
        if entry.name.endswith((".yaml", ".yml"))
    )


logger = logging.getLogger(__name__)


def _coerce_path(path: str | Path) -> Path:
    """Resolve ``path`` to a readable catalog file.

    A bare bundled name (``catalog-ai.yaml``) resolves to the packaged copy.
    The five shipped catalogs — AI, SSDF 1.2, FedRAMP 20x KSI, OSPS Baseline
    and the default — otherwise had no CLI surface at all: `--catalog
    catalog-ai.yaml` raised FileNotFoundError, and the only documented way in
    was an `importlib.resources` incantation that breaks under pipx, Windows
    and containers where the interpreter is `python3`. The filesystem is still
    consulted first, so a local file of the same name always wins.
    """
    candidate = Path(path).expanduser()
    if candidate.is_file():
        return candidate
    name = candidate.name
    if candidate == Path(name):
        with contextlib.suppress(FileNotFoundError):
            resolved = bundled_catalog_path(name)
            # The fallback is a real feature, but it must never be silent.
            # ``catalog.yaml`` is both the default bundled name and the most
            # likely name a user gives their own file: running from one
            # directory up turned `--catalog catalog.yaml` into "evaluate
            # against the stock 13 controls", verdict `ready`, exit 0, with
            # nothing in stdout, stderr or the bundle to say the org catalog
            # was never read. A substituted control set is a substituted
            # verdict.
            logger.warning(
                "Control catalog %r was not found on disk; falling back to the "
                "BUNDLED catalog of the same name (%s). The verdict will be "
                "computed against the bundled control set, not yours. Pass an "
                "explicit path (./%s) if you meant a local file.",
                str(path),
                resolved,
                name,
            )
            return resolved
    available = ", ".join(bundled_catalog_names())
    raise FileNotFoundError(
        f"Control catalog not found at {candidate}. Bundled catalogs available by name: {available}"
    )


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
    if not entries:
        # An empty catalog made the gate fail OPEN: zero controls means zero
        # gaps, so `build_summary` returned `ready` with coverage 0 and the
        # command exited 0. A truncated or half-written catalog therefore
        # passed every release silently. There is no honest verdict to give
        # for "nothing was checked", so refuse at the boundary.
        raise ValueError(
            f"Control catalog {source} has an empty 'controls' list. A catalog that "
            "defines no controls cannot evaluate a release: it would report `ready` "
            "because nothing was checked."
        )

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
