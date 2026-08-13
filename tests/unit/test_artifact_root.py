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

import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.paths import redact_path_in, relative_to_root

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


def _link_directory(link: Path, target: Path) -> bool:
    """Create a directory link, or report that this machine will not allow it."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    # Windows without Developer Mode refuses symlinks but allows junctions,
    # which is the shape a CI checkout actually uses there.
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        check=False,
    )
    return result.returncode == 0 and link.exists()


def test_a_symlinked_artifacts_directory_is_still_stripped(tmp_path: Path) -> None:
    """Resolving both sides made the flag fail OPEN through a link.

    An `artifacts/` directory that is a symlink or junction into a shared cache
    is a standard CI layout. `resolve()` follows the link out from under the
    root, `relative_to` raises, and the "outside the root" branch hands back
    the full absolute path — publishing exactly what the flag exists to hide.
    The lexical comparison the fix replaced got this case right, so trying it
    first is not a nicety.
    """
    repo = (tmp_path / "repo").resolve()
    cache = (tmp_path / "shared-cache").resolve()
    repo.mkdir()
    cache.mkdir()
    (cache / "semgrep.sarif").write_text(_SARIF, encoding="utf-8")

    if not _link_directory(repo / "artifacts", cache):
        pytest.skip("this machine does not allow creating directory links")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[repo / "artifacts"], artifact_root=repo
    ).collect()

    raw = report.evidence[0].raw
    assert raw is not None and raw.artifact_path is not None
    assert not Path(raw.artifact_path).is_absolute()
    assert str(cache) not in raw.artifact_path
    assert str(tmp_path) not in raw.artifact_path


def test_a_link_does_not_publish_the_directory_name_it_hides(tmp_path: Path) -> None:
    """Resolving leaked the target's name even when it was inside the root.

    A neutral `artifacts` link over `.internal-clientA-staging` is a deliberate
    choice; recording the target's real directory name publishes precisely the
    thing the link was covering.
    """
    repo = (tmp_path / "repo").resolve()
    hidden = repo / ".internal-clientA-staging"
    hidden.mkdir(parents=True)
    (hidden / "semgrep.sarif").write_text(_SARIF, encoding="utf-8")

    if not _link_directory(repo / "artifacts", hidden):
        pytest.skip("this machine does not allow creating directory links")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[repo / "artifacts"], artifact_root=repo
    ).collect()

    raw = report.evidence[0].raw
    assert raw is not None and raw.artifact_path is not None
    assert "internal-clientA-staging" not in raw.artifact_path
    assert raw.artifact_path == str(Path("artifacts") / "semgrep.sarif")


def test_the_reason_is_redacted_even_when_the_error_escapes_its_backslashes(
    workspace: Path,
) -> None:
    """`str(OSError)` renders the filename through `repr()`, doubling backslashes.

    So a plain `str.replace(str(path), ...)` never matched on Windows, and the
    `reason` shipped the absolute path — including the username — while the
    `path` field beside it was correctly stripped.
    """
    absolute = workspace / "artifacts" / "broken.json"
    doubled = str(absolute).replace("\\", "\\\\")
    message = f"[Errno 13] Permission denied: {doubled!s} while reading {absolute}"

    redacted = redact_path_in(message, absolute, Path("artifacts") / "broken.json")

    assert str(workspace) not in redacted
    assert doubled not in redacted
    assert "broken.json" in redacted


def test_redaction_is_a_no_op_when_nothing_was_rewritten(tmp_path: Path) -> None:
    path = tmp_path / "a.json"
    message = f"Invalid JSON in {path}"
    assert redact_path_in(message, path, path) == message


_TRIVY = """{
  "SchemaVersion": 2,
  "ArtifactName": "%(root)s/services/api",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "%(root)s/services/api/requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-1", "PkgName": "flask",
         "InstalledVersion": "2.0.0", "Severity": "HIGH"}
      ]
    }
  ]
}"""


def test_scanner_reported_paths_in_metadata_are_stripped_too(tmp_path: Path) -> None:
    """Trivy's own ArtifactName and Target carried the full local path.

    `raw.artifact_path` was correctly rewritten while
    `metadata.artifact_name` and `metadata.targets` beside it still read
    `/home/alice/clients/acme/...`. The flag promises the *bundle* records
    repo-relative paths, and metadata is in the bundle.
    """
    repo = (tmp_path / "repo").resolve()
    artifacts = repo / "artifacts"
    artifacts.mkdir(parents=True)
    (artifacts / "trivy.json").write_text(_TRIVY % {"root": repo.as_posix()}, encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[artifacts], artifact_root=repo
    ).collect()

    assert report.evidence, "the Trivy report should have produced evidence"
    for evidence in report.evidence:
        blob = json.dumps(evidence.model_dump(mode="json"))
        assert str(repo) not in blob
        assert repo.as_posix() not in blob


def test_a_scanner_target_that_is_not_a_local_path_is_left_alone(tmp_path: Path) -> None:
    """An image reference is not a path; rewriting it would corrupt the record."""
    repo = (tmp_path / "repo").resolve()
    artifacts = repo / "artifacts"
    artifacts.mkdir(parents=True)
    # Longest pattern first: the shorter one is a prefix of it.
    image = _TRIVY.replace(
        "%(root)s/services/api/requirements.txt", "acme/api:1.0 (debian 12)"
    ).replace("%(root)s/services/api", "acme/api:1.0")
    (artifacts / "trivy.json").write_text(image, encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[artifacts], artifact_root=repo
    ).collect()

    metadata = report.evidence[0].metadata
    assert metadata["artifact_name"] == "acme/api:1.0"
    assert metadata["targets"] == ["acme/api:1.0 (debian 12)"]
