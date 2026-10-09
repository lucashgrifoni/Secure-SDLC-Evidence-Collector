"""Run release guards locally, without signing or publishing artifacts."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
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


@pytest.mark.parametrize(
    ("suffix", "condition"),
    [
        ("whl", "missing"),
        ("whl", "changed"),
        ("whl", "extra"),
        ("tar.gz", "absent"),
        ("both", "empty"),
    ],
)
def test_distribution_gate_blocks_an_incomplete_or_different_wheel(
    suffix: str, condition: str, tmp_path: Path
) -> None:
    first, second = _identical_builds(tmp_path)
    _break(first, second, suffix, condition)
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode != 0, result.stdout


@pytest.mark.parametrize("condition", ["missing", "changed", "extra"])
def test_distribution_gate_only_warns_on_an_sdist_rebuild_mismatch(
    condition: str, tmp_path: Path
) -> None:
    """The rewritten sdist normaliser has not yet run in a real release.

    The job runs after the tag exists, so failing here burns the version, as
    happened to 3.0.0. A back-to-back sdist mismatch stays a warning until a
    release log confirms the new normaliser; the wheel stays fatal.
    """
    first, second = _identical_builds(tmp_path)
    _break(first, second, "tar.gz", condition)
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "::warning::" in result.stdout
    assert "::error::" not in result.stdout


def test_distribution_gate_accepts_identical_wheel_and_sdist(tmp_path: Path) -> None:
    _identical_builds(tmp_path)
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "::warning::" not in result.stdout


def _identical_builds(tmp_path: Path) -> tuple[Path, Path]:
    first, second = tmp_path / "dist", tmp_path / "dist-recheck"
    for directory in (first, second):
        directory.mkdir()
        (directory / "pkg.whl").write_bytes(b"wheel")
        (directory / "pkg.tar.gz").write_bytes(b"sdist")
    return first, second


def _break(first: Path, second: Path, suffix: str, condition: str) -> None:
    if condition == "empty":
        for directory in (first, second):
            for artifact in directory.iterdir():
                artifact.unlink()
    elif condition == "absent":
        (first / f"pkg.{suffix}").unlink()
        (second / f"pkg.{suffix}").unlink()
    elif condition == "missing":
        (second / f"pkg.{suffix}").unlink()
    elif condition == "changed":
        (second / f"pkg.{suffix}").write_bytes(b"different")
    elif condition == "extra":
        (second / f"unexpected.{suffix}").write_bytes(b"extra")


def test_container_build_copies_every_declared_license_file() -> None:
    """The image builds its wheel from a narrow COPY of the tree.

    pyproject declares THIRD_PARTY_LICENSES.md as a license file for the
    BSD-2-Clause CVSS port. Left out of the Docker build context, setuptools
    only warns and the image's wheel ships without it.
    """
    declared = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"][
        "license-files"
    ]
    copied = {
        token
        for line in Path("Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("COPY ") and "--from=" not in line
        for token in line.split()[1:-1]
    }
    assert set(declared) <= copied, f"Dockerfile does not copy {set(declared) - copied}"


def test_changelog_has_no_section_above_the_release_please_insertion_point() -> None:
    """release-please owns CHANGELOG.md and inserts each release before the
    first heading matching its version pattern. A hand-written section such
    as `## Unreleased` would stay above every generated entry."""
    text = Path("CHANGELOG.md").read_text(encoding="utf-8")
    insertion = re.search(r"\n###? v?[0-9[]", text)
    assert insertion is not None
    assert not re.search(r"^#{2,3} ", text[: insertion.start()], re.MULTILINE), (
        "CHANGELOG.md has a heading above the release-please insertion point"
    )
