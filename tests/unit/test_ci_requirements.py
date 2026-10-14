"""Hash-locked CI requirements stay in step with pyproject.toml.

The workflows, the Dockerfile and the devcontainer install third-party code
from `.github/requirements/*.txt` with `--require-hashes`, then the project
itself with `--no-deps`. The `.in` files those locks are compiled from repeat
the ranges in pyproject.toml, because Dependabot recompiles a lock from the
`.in` files in its own directory and cannot read pyproject.toml from there.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

_REQUIREMENTS = Path(".github/requirements")
_PYPROJECT = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
# Installs the release the CALLER picks, in the caller's repository, where
# these locks do not exist.
_CALLER_CHOSEN = {Path(".github/workflows/reusable-evidence-collection.yml")}


def _specs(name: str) -> set[str]:
    lines = (_REQUIREMENTS / name).read_text(encoding="utf-8").splitlines()
    return {
        line.replace(" ", "") for line in lines if line.strip() and not line.startswith(("#", "-"))
    }


def _extras(*names: str) -> set[str]:
    optional = _PYPROJECT["optional-dependencies"]
    return {spec.replace(" ", "") for name in names for spec in optional[name]}


@pytest.mark.parametrize(
    ("in_file", "expected"),
    [
        ("runtime.in", {spec.replace(" ", "") for spec in _PYPROJECT["dependencies"]}),
        ("dev.in", _extras("dev", "api", "logs")),
        ("docs.in", _extras("docs")),
    ],
)
def test_lock_inputs_mirror_pyproject(in_file: str, expected: set[str]) -> None:
    assert _specs(in_file) == expected


@pytest.mark.parametrize("in_file", ["dev.in", "docs.in", "sbom.in"])
def test_project_locks_build_on_the_runtime_input(in_file: str) -> None:
    lines = (_REQUIREMENTS / in_file).read_text(encoding="utf-8").splitlines()
    assert "-r runtime.in" in lines


@pytest.mark.parametrize("in_file", sorted(p.name for p in _REQUIREMENTS.glob("*.in")))
def test_every_input_has_a_universal_hashed_lock(in_file: str) -> None:
    lock = (_REQUIREMENTS / in_file).with_suffix(".txt").read_text(encoding="utf-8")
    header = lock.splitlines()[1]
    for option in ("--universal", "--generate-hashes", "--python-version 3.12"):
        assert option in header, f"{in_file}: lock not compiled with {option}"
    assert "--hash=sha256:" in lock


def _pip_installs(text: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if re.search(r"\bpip3? install\b", line)]


def _workflow_scripts(path: Path) -> list[str]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        step["run"]
        for job in workflow["jobs"].values()
        for step in job.get("steps", [])
        if "run" in step
    ]


@pytest.mark.parametrize(
    "path",
    sorted(p for p in Path(".github/workflows").glob("*.yml") if p not in _CALLER_CHOSEN),
    ids=lambda p: p.name,
)
def test_workflow_pip_installs_are_hash_locked_or_local(path: Path) -> None:
    for script in _workflow_scripts(path):
        for line in _pip_installs(script):
            locked = "--require-hashes" in line
            local = "--no-deps" in line and ("-e ." in line or ".whl" in line)
            assert locked or local, f"{path.name}: unpinned install: {line}"
