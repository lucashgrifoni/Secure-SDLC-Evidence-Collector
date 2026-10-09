"""A stale output lock must stop the CLI with exit 3 and say how to recover.

Real subprocesses on purpose: exit 3 for an unhandled OSError is decided in
`main()`, which Typer's `CliRunner` never executes.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "evidence_collector.cli.main", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _run_args(artifacts: Path, output: Path) -> tuple[str, ...]:
    return (
        "run",
        "--application",
        "a",
        "--repository",
        "o/r",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--artifacts-dir",
        str(artifacts),
        "--output-dir",
        str(output),
    )


@pytest.mark.integration
def test_sarif_with_a_stale_lock_exits_3_and_names_the_lock(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    built = _cli(*_run_args(artifacts, tmp_path / "bundle"))
    assert built.returncode in (0, 1, 2), built.stdout + built.stderr
    lock = tmp_path / ".gaps.sarif.lock"
    lock.write_text("pid=1\n", encoding="ascii")
    bundle = tmp_path / "bundle" / "bundle.json"
    result = _cli("sarif", str(bundle), "--output", str(tmp_path / "gaps.sarif"))
    assert result.returncode == 3, result.stdout + result.stderr
    output = " ".join((result.stdout + result.stderr).split())
    assert ".gaps.sarif.lock" in output
    assert "delete only" in output
    assert not (tmp_path / "gaps.sarif").exists()


@pytest.mark.integration
def test_run_with_a_stale_lock_exits_3_and_a_clean_run_leaves_no_lock(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    lock = output / ".bundle.json.lock"
    lock.write_text("pid=1\n", encoding="ascii")

    blocked = _cli(*_run_args(artifacts, output))
    assert blocked.returncode == 3, blocked.stdout + blocked.stderr
    assert ".bundle.json.lock" in " ".join((blocked.stdout + blocked.stderr).split())
    assert sorted(path.name for path in output.iterdir()) == [".bundle.json.lock"]

    lock.unlink()
    clean = _cli(*_run_args(artifacts, output))
    assert clean.returncode in (0, 1, 2), clean.stdout + clean.stderr
    names = sorted(path.name for path in output.iterdir())
    assert names == ["bundle.json", "report.md", "summary.html"], names
