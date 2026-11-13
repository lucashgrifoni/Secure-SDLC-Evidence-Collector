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
from packaging.version import Version

_REQUIREMENTS = Path(".github/requirements")
_PYPROJECT = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
# Installs the release the CALLER picks, in the caller's repository, where
# these locks do not exist.
_CALLER_CHOSEN = {Path(".github/workflows/reusable-evidence-collection.yml")}
# First release that fixes the advisories raised against these locks. A pin
# below it installs a known vulnerability, so a floor only ever moves up.
_ADVISORY_FIXES = {
    "certifi": Version("2026.10.18"),  # GHSA-6q48-6c7w-9gw2
    "filelock": Version("4.2.1"),  # GHSA-v4x8-3wr5-3wq8 and the rest of that batch
    "opentelemetry-api": Version("1.45.2"),  # GHSA-mf5v-w3w3-f6cg, GHSA-xcq7-p3pf-p88h
    "uv": Version("0.13.4"),  # GHSA-hq85-5cpj-mr62
    "virtualenv": Version("21.14.9"),  # GHSA-c978-59m8-c77v and the rest of that batch
}
# Pins no lock refresh can move. Every semgrep release up to 1.185.0 requires
# opentelemetry-api~=1.37.0 and mcp==1.29.0. The sast-semgrep job runs
# `semgrep scan` without --trace and never starts the MCP server.
_HELD_BY_UPSTREAM = {"semgrep.txt": {"opentelemetry-api"}}


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


def _pins(lock: str) -> list[tuple[str, Version]]:
    text = (_REQUIREMENTS / lock).read_text(encoding="utf-8")
    pins = re.findall(r"^([\w.-]+)==([^\s;]+)", text, flags=re.MULTILINE)
    return [(name.lower(), Version(version)) for name, version in pins]


@pytest.mark.parametrize("lock", sorted(p.name for p in _REQUIREMENTS.glob("*.txt")))
def test_no_lock_pins_a_release_older_than_an_advisory_fix(lock: str) -> None:
    vulnerable = [
        f"{name}=={version}"
        for name, version in _pins(lock)
        if name in _ADVISORY_FIXES
        and version < _ADVISORY_FIXES[name]
        and name not in _HELD_BY_UPSTREAM.get(lock, set())
    ]
    assert not vulnerable, f"{lock}: pinned below the advisory fix: {vulnerable}"


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
