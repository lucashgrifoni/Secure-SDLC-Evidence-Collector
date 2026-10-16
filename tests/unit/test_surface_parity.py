"""The three CI surfaces and the page that compares them stay in step.

The composite Action, the reusable workflow and the GitLab component take
largely the same inputs, and drifted apart without anyone noticing: the
reusable workflow had no `fail-on`, recorded every bundle as `production`
and resolved catalogs differently, and the component fails on a release the
other two pass. None of it was written down outside the YAML.

docs/reusable_workflow.md now carries one table with every input of every
surface and its default. These tests read that table and the three files, so
a surface cannot gain, lose or change an input without the page saying so,
and a difference between surfaces cannot appear without a note.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_DOC = Path("docs/reusable_workflow.md")
_ACTION = Path("action.yml")
_REUSABLE = Path(".github/workflows/reusable-evidence-collection.yml")
_COMPONENT = Path("examples/gitlab-component/templates/collect.yml")
_LEGACY_GITLAB = Path("examples/gitlab-ci/secure-sdlc-evidence.yml")

_REQUIRED = "required"
_ABSENT = "—"
_SURFACES = ("Action", "Reusable workflow", "GitLab component")


def _cell(default: Any) -> str:
    if isinstance(default, bool):
        return "true" if default else "false"
    return '""' if default == "" else str(default)


def _defaults(inputs: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {
        name: _cell(spec["default"]) if "default" in spec else _REQUIRED
        for name, spec in inputs.items()
    }


def _surfaces() -> dict[str, dict[str, str]]:
    action = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    reusable = yaml.safe_load(_REUSABLE.read_text(encoding="utf-8"))
    # PyYAML reads the bare key `on` as the boolean True.
    trigger = reusable.get("on", reusable.get(True))
    component = next(yaml.safe_load_all(_COMPONENT.read_text(encoding="utf-8")))
    return {
        "Action": _defaults(action["inputs"]),
        "Reusable workflow": _defaults(trigger["workflow_call"]["inputs"]),
        "GitLab component": _defaults(component["spec"]["inputs"]),
    }


def _split_row(line: str) -> list[str]:
    cells = re.split(r"(?<!\\)\|", line.strip())[1:-1]
    return [cell.strip().replace("\\|", "|") for cell in cells]


def _unquote(cell: str) -> str:
    if cell.startswith("`") and cell.endswith("`") and len(cell) > 1:
        return cell[1:-1]
    return cell


def _documented() -> dict[str, dict[str, str]]:
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    header = next(
        i for i, line in enumerate(lines) if _split_row(line)[:4] == ["Input", *_SURFACES]
    )
    rows: dict[str, dict[str, str]] = {}
    for line in lines[header + 2 :]:
        if not line.startswith("|"):
            break
        name, *values, note = _split_row(line)
        rows[_unquote(name)] = {
            **{surface: _unquote(value) for surface, value in zip(_SURFACES, values, strict=True)},
            "Notes": note,
        }
    return rows


@pytest.fixture(scope="module")
def documented() -> dict[str, dict[str, str]]:
    return _documented()


@pytest.fixture(scope="module")
def surfaces() -> dict[str, dict[str, str]]:
    return _surfaces()


def test_the_matrix_lists_every_input_of_every_surface(
    documented: dict[str, dict[str, str]], surfaces: dict[str, dict[str, str]]
) -> None:
    declared = set().union(*(set(inputs) for inputs in surfaces.values()))
    assert set(documented) == declared, (
        f"undocumented: {sorted(declared - set(documented))}; "
        f"documented but gone: {sorted(set(documented) - declared)}"
    )


@pytest.mark.parametrize("surface", _SURFACES)
def test_every_documented_default_matches_the_surface(
    documented: dict[str, dict[str, str]], surfaces: dict[str, dict[str, str]], surface: str
) -> None:
    actual = surfaces[surface]
    wrong = {
        name: (row[surface], actual.get(name, _ABSENT))
        for name, row in documented.items()
        if row[surface] != actual.get(name, _ABSENT)
    }
    assert not wrong, f"{surface}: documented vs actual {wrong}"


def test_every_difference_between_surfaces_has_a_note(
    documented: dict[str, dict[str, str]],
) -> None:
    unexplained = [
        name
        for name, row in documented.items()
        if len({row[surface] for surface in _SURFACES}) > 1 and not row["Notes"]
    ]
    assert not unexplained, f"inputs that differ between surfaces without a note: {unexplained}"


def test_the_gate_inputs_the_owner_kept_are_documented(
    documented: dict[str, dict[str, str]],
) -> None:
    """No default flips in 4.x: the GitHub surfaces keep not_ready, GitLab conditional."""
    assert documented["fail-on"]["Action"] == "not_ready"
    assert documented["fail-on"]["Reusable workflow"] == "not_ready"
    assert documented["fail-on"]["GitLab component"] == "conditional"
    assert documented["environment"]["Action"] == "production"


def test_the_legacy_gitlab_template_points_at_the_component() -> None:
    """The template word-splits its arguments; the component replaced it."""
    header = _LEGACY_GITLAB.read_text(encoding="utf-8").split(".secure-sdlc-evidence:")[0]
    assert "DEPRECATED" in header
    assert "examples/gitlab-component" in header
    assert "secure-sdlc-evidence-component/collect" in header
