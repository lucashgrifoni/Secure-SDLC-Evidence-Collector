"""Unit tests for entry-point plugin discovery.

`plugins.py` is public API on two surfaces — the `sdlc-evidence plugins`
command and the REST `/plugins` endpoint — and had no coverage at all, which
is how its docstring came to name six built-in parsers while `pyproject.toml`
registered eight.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from evidence_collector import plugins
from evidence_collector.plugins import (
    COLLECTOR_GROUP,
    PARSER_GROUP,
    discover_collectors,
    discover_parsers,
    list_plugins,
)


def _project_root() -> Path:
    """Resolve the repo root from this package, not from the cwd.

    An earlier guard test in this campaign passed vacuously because it built
    a cwd-relative path and found nothing when pytest ran from elsewhere.
    """
    return Path(plugins.__file__).resolve().parents[2]


def _declared_entry_points(group: str) -> set[str]:
    pyproject = _project_root() / "pyproject.toml"
    if not pyproject.is_file():  # pragma: no cover - only in a wheel-only install
        pytest.skip("pyproject.toml is not shipped in an installed distribution")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return set(data["project"]["entry-points"][group])


def _names_in_docstring(doc: str) -> set[str]:
    """The ``name`` tokens from the sentence that lists the built-ins.

    The two docstrings introduce their list differently, so both openers are
    accepted rather than forcing one phrasing on the prose.
    """
    for opener in ("stable names:", "Built-in names:"):
        if opener in doc:
            sentence = doc.split(opener, 1)[1].split("\n\n", 1)[0]
            return set(re.findall(r"``([a-z]+)``", sentence))
    raise AssertionError("docstring no longer introduces its list of built-in names")


def test_the_documented_built_in_parsers_are_the_ones_actually_registered() -> None:
    """Keeps the docstring honest, since prose drifts and a test does not.

    `vsa` and `provenance` were added to `pyproject.toml` and never reached
    the list that calls those names stable. A reader following the docstring
    would not know either exists.
    """
    documented = _names_in_docstring(discover_parsers.__doc__ or "")
    assert documented == _declared_entry_points(PARSER_GROUP)


def test_the_documented_built_in_collectors_are_the_ones_actually_registered() -> None:
    documented = _names_in_docstring(discover_collectors.__doc__ or "")
    assert documented == _declared_entry_points(COLLECTOR_GROUP)


def test_listing_plugins_does_not_execute_any_plugin_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The property that makes the REST endpoint and the CLI listing safe.

    `/plugins` is reachable by anyone who can reach the port, so listing must
    stay metadata-only: importing every third-party package registered in the
    environment on an unauthenticated GET would be a very different surface.
    `load()` is sabotaged here so that any call at all fails the test.
    """

    def explode(self: EntryPoint) -> object:
        raise AssertionError(f"list_plugins() loaded the {self.name!r} entry point")

    monkeypatch.setattr(EntryPoint, "load", explode)

    listing = list_plugins()
    assert "sarif" in listing["parsers"]
    assert "local" in listing["collectors"]

    # The same sabotage proves the test is not vacuous: discovery *does* load,
    # so if `load` were never wired up, this would pass silently too.
    with pytest.raises(AssertionError, match="loaded the"):
        discover_parsers()


def test_the_listing_is_sorted_so_the_endpoint_output_is_stable() -> None:
    listing = list_plugins()
    assert listing["parsers"] == sorted(listing["parsers"])
    assert listing["collectors"] == sorted(listing["collectors"])


def test_every_built_in_parser_resolves_to_something_callable() -> None:
    """A broken entry-point target only fails at `load()`, not at install."""
    for name, parser in discover_parsers().items():
        assert callable(parser), name


def test_every_built_in_collector_resolves_to_a_class() -> None:
    for name, collector in discover_collectors().items():
        assert isinstance(collector, type), name
