"""Run release guards locally, without signing or publishing artifacts."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml


def _jobs() -> dict[str, Any]:
    workflow = yaml.safe_load(
        Path(".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    )
    return cast(dict[str, Any], workflow["jobs"])


def _step(name: str) -> dict[str, Any]:
    return next(
        step
        for job in _jobs().values()
        for step in job.get("steps", [])
        if step.get("name") == name
    )


def _shell(script: str, directory: Path, **fields: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("release scripts require Bash")
    return subprocess.run(
        [bash, "-c", script],
        cwd=directory,
        env={**os.environ, **fields},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_every_release_checkout_uses_the_event_commit() -> None:
    checkouts = [
        step
        for job in _jobs().values()
        for step in job.get("steps", [])
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts
    assert all(step["with"].get("ref") == "${{ github.sha }}" for step in checkouts)


@pytest.mark.parametrize(
    ("event", "ref", "requested", "allowed"),
    [
        ("workflow_dispatch", "refs/heads/main", "v3.2.0", False),
        ("workflow_dispatch", "refs/tags/v3.2.0", "v3.2.1", False),
        ("workflow_dispatch", "refs/tags/v3.2.0", "v3.2.0", True),
        ("workflow_dispatch", "refs/tags/v3.2.0", 'v3.2.0"; exit 0; #', False),
        ("push", "refs/tags/v3.2.0", "", True),
    ],
)
def test_requested_tag_and_provenance_ref_must_agree(
    event: str, ref: str, requested: str, allowed: bool, tmp_path: Path
) -> None:
    script = _step("Resolve tag")["run"].replace("${{ github.event_name }}", event)
    result = _shell(
        script,
        tmp_path,
        INPUT_TAG=requested,
        EVENT_NAME=event,
        GITHUB_REF=ref,
        GITHUB_REF_NAME=ref.rsplit("/", 1)[-1],
        GITHUB_OUTPUT=str(tmp_path / "outputs"),
    )
    assert (result.returncode == 0) is allowed, result.stdout + result.stderr


@pytest.mark.parametrize("condition", ["missing", "changed", "extra", "empty"])
def test_distribution_gate_blocks_an_incomplete_or_different_rebuild(
    condition: str, tmp_path: Path
) -> None:
    first, second = tmp_path / "dist", tmp_path / "dist-recheck"
    first.mkdir()
    second.mkdir()
    if condition != "empty":
        for directory in (first, second):
            (directory / "pkg.whl").write_bytes(b"wheel")
            (directory / "pkg.tar.gz").write_bytes(b"sdist")
        if condition == "missing":
            (second / "pkg.tar.gz").unlink()
        elif condition == "changed":
            (second / "pkg.tar.gz").write_bytes(b"different")
        elif condition == "extra":
            (second / "unexpected.tar.gz").write_bytes(b"sdist")
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode != 0, result.stdout


def test_distribution_gate_accepts_identical_wheel_and_sdist(tmp_path: Path) -> None:
    for name in ("dist", "dist-recheck"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "pkg.whl").write_bytes(b"wheel")
        (directory / "pkg.tar.gz").write_bytes(b"sdist")
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
