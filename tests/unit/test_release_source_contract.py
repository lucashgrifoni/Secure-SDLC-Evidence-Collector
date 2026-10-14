"""Run release guards locally, without signing or publishing artifacts."""

from __future__ import annotations

import json
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
def test_distribution_gate_blocks_an_sdist_rebuild_mismatch(condition: str, tmp_path: Path) -> None:
    """4.0.0 published a reproducible sdist with the rewritten normaliser.

    Its release log shows "Reproducible distribution" for the sdist, so a
    back-to-back sdist mismatch now fails the job like a wheel mismatch.
    """
    first, second = _identical_builds(tmp_path)
    _break(first, second, "tar.gz", condition)
    result = _shell(_step("Compare SHA-256 between back-to-back builds")["run"], tmp_path)
    assert result.returncode != 0, result.stdout
    assert "::error::" in result.stdout


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


def test_release_please_never_rewrites_a_workflow_file() -> None:
    # The release-please App token has no `workflows` permission, so a
    # workflow file in extra-files makes every run fail with "Error adding to
    # tree" and the release PR stops updating.
    config = json.loads(Path(".github/release-please-config.json").read_text(encoding="utf-8"))
    paths = [
        entry if isinstance(entry, str) else entry["path"]
        for package in config["packages"].values()
        for entry in package.get("extra-files", [])
    ]
    assert paths, "expected the version-bearing extra-files to be configured"
    assert not [p for p in paths if p.startswith(".github/workflows/")]


_REPOSITORY = "lucashgrifoni/Secure-SDLC-Evidence-Collector"
# `uses: <repo>@vX.Y.Z` and raw URLs `<repo>/vX.Y.Z/...` that pin this project.
_INLINE_SELF_PIN = re.compile(re.escape(_REPOSITORY) + r"(?:@|/)v(\d+\.\d+\.\d+)")
# A pre-commit `rev:` line, commented out or not.
_REV_LINE = re.compile(r"^[\s#]*rev:\s*v(\d+\.\d+\.\d+)")


def _self_pins(lines: list[str]) -> list[tuple[int, str]]:
    """(line number, version) for every line that pins a release of this project."""
    pins: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        inline = _INLINE_SELF_PIN.search(line)
        if inline:
            pins.append((index + 1, inline.group(1)))
            continue
        rev = _REV_LINE.match(line)
        if rev is None:
            continue
        # A `rev:` belongs to the nearest `repo:` above it in the same block.
        repo_line = next(
            (above for above in reversed(lines[max(0, index - 4) : index]) if "repo:" in above),
            "",
        )
        if _REPOSITORY in repo_line:
            pins.append((index + 1, rev.group(1)))
    return pins


def test_every_pinned_release_of_this_project_is_bumped_by_release_please() -> None:
    """README and `.pre-commit-hooks.yaml` still said `rev: v4.0.0` after 4.1.0.

    release-please bumped the Action and GitLab examples because they are in
    `extra-files`, but the two pre-commit examples were not, so they went stale
    on the first release after they were written. Every line outside the
    workflows (which the release-please App may not write) and CHANGELOG.md
    that pins a tag of this repository must carry the current version, the
    `x-release-please-version` marker, and live in a file listed in
    `extra-files` - otherwise the next release leaves it behind again.
    """
    tracked = subprocess.run(
        ["git", "-c", f"safe.directory={Path.cwd()}", "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    if tracked.returncode != 0:
        pytest.skip("git is not usable here; cannot list tracked files")
    version = json.loads(Path(".github/.release-please-manifest.json").read_text(encoding="utf-8"))[
        "."
    ]
    config = json.loads(Path(".github/release-please-config.json").read_text(encoding="utf-8"))
    managed = {
        entry if isinstance(entry, str) else entry["path"]
        for package in config["packages"].values()
        for entry in package.get("extra-files", [])
    }

    problems: list[str] = []
    for name in filter(None, tracked.stdout.split("\0")):
        if name.startswith(".github/workflows/") or name == "CHANGELOG.md":
            continue
        try:
            lines = Path(name).read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for number, pinned in _self_pins(lines):
            line = lines[number - 1]
            if pinned != version:
                problems.append(f"{name}:{number} pins v{pinned}, current is v{version}")
            if "x-release-please-version" not in line:
                problems.append(f"{name}:{number} has no x-release-please-version marker")
            if name not in managed:
                problems.append(f"{name}:{number} is not in release-please extra-files")
    assert not problems, "\n".join(problems)


def test_self_pin_detection_covers_the_forms_in_use() -> None:
    """The scanner above must actually see the pins it is meant to police."""
    lines = [
        "repos:",
        f"  - repo: https://github.com/{_REPOSITORY}",
        "    # a comment between repo and rev",
        "    rev: v4.0.0",
        "  - repo: https://github.com/pre-commit/pre-commit-hooks",
        "    rev: v4.6.0",
        f"#     - repo: https://github.com/{_REPOSITORY}",
        "#       rev: v3.0.0",
        f"- uses: {_REPOSITORY}@v2.0.0",
        f"'https://raw.githubusercontent.com/{_REPOSITORY}/v1.0.0/x.yml'",
        f"https://github.com/{_REPOSITORY}/releases/tag/v2.0.0",
    ]
    assert _self_pins(lines) == [(4, "4.0.0"), (8, "3.0.0"), (9, "2.0.0"), (10, "1.0.0")]
