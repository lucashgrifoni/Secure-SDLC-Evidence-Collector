"""`--artifact-root` must actually strip local paths from the bundle.

Its help text says it exists "so the bundle records repo-relative paths
instead of leaking local filesystem locations". Two ways it did not:

- `Path.relative_to` compares the strings as given, so any mismatch in how
  the two sides were expressed — `--artifact-root .` against absolute artifact
  paths, an absolute root against a relative `--artifacts-dir` — raised
  `ValueError`, which was caught and fell back to the full path. The flag
  silently did nothing while the operator believed the paths were stripped.
- `collection_errors` was never rewritten at all, neither its `path` nor the
  `reason` that embeds the path in the parser's own message.

A privacy control that fails open and stays quiet is worse than no control.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.paths import relative_to_root

_SARIF = (
    '{"version": "2.1.0", "runs": [{"tool": {"driver": '
    '{"name": "semgrep", "rules": []}}, "results": []}]}'
)


@pytest.fixture
def workspace(tmp_path: Path) -> Iterator[Path]:
    """A repo-shaped directory, with the CWD set to it as CI would have it."""
    root = tmp_path.resolve()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "semgrep.sarif").write_text(_SARIF, encoding="utf-8")
    (artifacts / "broken.json").write_text('{"truncated', encoding="utf-8")
    previous = Path.cwd()
    os.chdir(root)
    try:
        yield root
    finally:
        os.chdir(previous)


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890")


@pytest.mark.parametrize(
    ("dirs_are_absolute", "root_is_absolute"),
    [(True, False), (True, True), (False, False), (False, True)],
)
def test_paths_are_stripped_however_the_two_sides_are_expressed(
    workspace: Path, dirs_are_absolute: bool, root_is_absolute: bool
) -> None:
    """The flag must work for every combination a real invocation produces.

    `--artifacts-dir artifacts --artifact-root .` from a CI checkout, or
    absolute paths from a runner that expands them — all four combinations
    describe the same repository, and all four must produce the same
    repo-relative path in the bundle.
    """
    artifacts = workspace / "artifacts" if dirs_are_absolute else Path("artifacts")
    root = workspace if root_is_absolute else Path(".")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[artifacts], artifact_root=root
    ).collect()

    raw = report.evidence[0].raw
    assert raw is not None and raw.artifact_path is not None
    recorded = Path(raw.artifact_path)
    assert not recorded.is_absolute()
    assert recorded == Path("artifacts") / "semgrep.sarif"
    assert str(workspace) not in str(recorded)


def test_collection_errors_are_stripped_too(workspace: Path) -> None:
    """The leak nobody checks: the failure path, in the published bundle."""
    report = LocalArtifactCollector(
        _release(),
        artifacts_dirs=[workspace / "artifacts"],
        artifact_root=workspace,
    ).collect()

    assert len(report.errors) == 1
    error = report.errors[0]
    assert not error.path.is_absolute()
    assert error.path == Path("artifacts") / "broken.json"
    # The parser embeds the path in its message, so the message leaks too.
    assert str(workspace) not in error.reason
    assert "broken.json" in error.reason


def test_without_the_flag_paths_are_left_exactly_as_they_were(workspace: Path) -> None:
    """Opt-in stays opt-in: no root means no rewriting, absolute or otherwise."""
    absolute_dir = workspace / "artifacts"
    report = LocalArtifactCollector(_release(), artifacts_dirs=[absolute_dir]).collect()

    raw = report.evidence[0].raw
    assert raw is not None and raw.artifact_path is not None
    assert Path(raw.artifact_path).is_absolute()


def test_a_path_outside_the_root_is_returned_unchanged(tmp_path: Path) -> None:
    """Never emit a `../../..` chain: it leaks the same thing and is wrong.

    An artifact genuinely outside the root — a scanner writing to a shared
    cache, an absolute path from another checkout — cannot be expressed
    relative to it in any useful way.
    """
    root = (tmp_path / "repo").resolve()
    root.mkdir()
    outside = (tmp_path / "elsewhere" / "scan.sarif").resolve()

    assert relative_to_root(outside, root) == outside


def test_relative_to_root_is_a_no_op_without_a_root(tmp_path: Path) -> None:
    assert relative_to_root(tmp_path / "x.json", None) == tmp_path / "x.json"
