"""Plugin discovery for parsers and collectors.

The collector exposes two entry-point groups so third-party packages
can extend it without forking:

- ``evidence_collector.parsers`` — values must be callables that accept
  a ``str | pathlib.Path`` and return a ``ParsedArtifact``-shaped
  dataclass (see ``parsers/_common.py`` for the contract).
- ``evidence_collector.collectors`` — values must be classes that
  expose a ``collect()`` method returning a ``LocalCollectionReport``
  (or a compatible structure).

The built-in parsers and collectors are themselves registered through
these entry-point groups in ``pyproject.toml`` so that a downstream
caller can iterate over a single, uniform list.

Example — adding a custom parser from a third-party package::

    # in third_party_pkg/pyproject.toml
    [project.entry-points."evidence_collector.parsers"]
    fortify = "third_party_pkg.parsers.fortify:parse_fortify"

After installation, ``discover_parsers()['fortify']`` resolves to that
callable. See ``docs/plugins.md`` for the full contract.

This module deliberately keeps a narrow surface — discovery only. It
does not auto-wire plugins into ``LocalArtifactCollector``; consumers
that want plugin parsers in the run pipeline should call
``discover_parsers()`` and dispatch explicitly. Auto-wiring is tracked
separately in the maturity roadmap (T4.1 follow-up).
"""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint, entry_points
from typing import Any

PARSER_GROUP = "evidence_collector.parsers"
COLLECTOR_GROUP = "evidence_collector.collectors"


def _resolve(group: str) -> dict[str, EntryPoint]:
    # `importlib.metadata.entry_points` returns a SelectableGroups in
    # 3.10+; we use the modern `select` API exclusively.
    return {ep.name: ep for ep in entry_points(group=group)}


def discover_parsers() -> dict[str, Callable[..., Any]]:
    """Return a mapping of parser-name → callable.

    Keys come from the entry-point name. Built-in parsers register under
    stable names: ``sarif``, ``sbom``, ``junit``, ``zap``, ``attestation``,
    ``exception``, ``vsa`` and ``provenance`` — the last two were added to
    ``pyproject.toml`` without reaching this list.

    Third-party plugins can register additional names, or shadow a built-in
    by declaring the same name; last load wins and load order is
    unspecified, so a name collision is not a supported way to override.
    Treat it as a trust question rather than a configuration one: a package
    installed in the environment can decide what parses an artifact, and the
    bundle does not record which implementation ran. That matters only for a
    caller that dispatches through this function — the ``run`` pipeline
    calls the built-in parsers directly and loads no plugin code — so it is
    a constraint on the auto-wiring in the roadmap, not on today's pipeline.

    Note also that this loads *every* registered entry point, not just the
    one a caller wants, and a plugin that raises on import propagates out of
    here. That is deliberate: a plugin the operator installed and that
    cannot load is worth failing over, not skipping in silence.
    """
    return {name: ep.load() for name, ep in _resolve(PARSER_GROUP).items()}


def discover_collectors() -> dict[str, type[Any]]:
    """Return a mapping of collector-name → class.

    Built-in names: ``local``, ``github``, ``gitlab``. The class is
    expected to expose a constructor compatible with the built-ins'
    keyword arguments; see ``docs/plugins.md`` for the contract.
    """
    return {name: ep.load() for name, ep in _resolve(COLLECTOR_GROUP).items()}


def list_plugins() -> dict[str, list[str]]:
    """Return a flat listing for the ``sdlc-evidence plugins`` command."""
    return {
        "parsers": sorted(_resolve(PARSER_GROUP)),
        "collectors": sorted(_resolve(COLLECTOR_GROUP)),
    }
