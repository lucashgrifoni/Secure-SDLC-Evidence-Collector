"""The exit code must never make a crash look like a release verdict.

`run`, `evaluate` and `bundle` encode the verdict in the exit status: 0 ready,
1 conditional, 2 not_ready. Any exception that escaped a command reached
Click's default handler, which exits **1** — the same code as `conditional`.
Measured on v2.3.0, all of these exited 1 with a Rich-rendered traceback and no
bundle written:

* `run --commit-sha abc` (ValidationError: too short)
* `run --catalog nope.yaml` (FileNotFoundError)
* `evaluate --evidence gone.json` (OSError escaping a narrow except)
* `controls --catalog catalog-ai.yaml` (before CAT-01 was fixed)

A pipeline following the documented gate semantics reads that as "conditional,
proceed with a warning" — on a run that produced nothing at all.

These tests spawn a real subprocess on purpose. Every other CLI test uses
Typer's `CliRunner`, which invokes `app` directly and therefore never executes
`main()` — exactly where the guard lives, and why the gap survived. They double
as the only coverage of the `[project.scripts]` entrypoint path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_MODULE = "evidence_collector.cli.main"


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", _MODULE, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        check=False,
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    ("label", "args"),
    [
        (
            "short commit sha",
            (
                "run",
                "--application",
                "a",
                "--repository",
                "o/r",
                "--release-id",
                "1",
                "--commit-sha",
                "abc",
            ),
        ),
        (
            "missing catalog",
            (
                "run",
                "--application",
                "a",
                "--repository",
                "o/r",
                "--release-id",
                "1",
                "--commit-sha",
                "abcdef1234567890",
                "--catalog",
                "definitely-not-here.yaml",
            ),
        ),
        ("missing catalog on controls", ("controls", "--catalog", "definitely-not-here.yaml")),
    ],
)
def test_unhandled_failure_exits_three_without_a_traceback(
    label: str, args: tuple[str, ...], tmp_path: Path
) -> None:
    extra = ("--output-dir", str(tmp_path / "out")) if args[0] == "run" else ()
    result = _run(*args, *extra)

    assert result.returncode == 3, f"{label}: expected 3, got {result.returncode}"
    combined = result.stdout + result.stderr
    assert "Traceback" not in combined, f"{label}: raw traceback leaked to the user"
    # And the user is told what to do about it.
    assert "--verbose" in combined


@pytest.mark.integration
def test_failure_is_reported_as_ndjson_under_json_logs() -> None:
    """The NDJSON contract must hold on the error path too.

    Under `--json-logs` a crash used to leave stdout completely empty while the
    Rich traceback went to stderr, so a consumer parsing NDJSON saw nothing at
    all and could not distinguish a crash from a silent success.
    """
    result = _run("--json-logs", "controls", "--catalog", "definitely-not-here.yaml")

    assert result.returncode == 3
    events = [
        json.loads(line)
        for line in (result.stdout + result.stderr).splitlines()
        if line.strip().startswith("{")
    ]
    failures = [e for e in events if e.get("event") == "command_failed"]
    assert failures, f"no command_failed event emitted; got {events}"
    assert failures[0]["error_type"] == "FileNotFoundError"


@pytest.mark.integration
def test_verdict_exit_codes_are_untouched(tmp_path: Path, sample_release_root: Path) -> None:
    """The guard must not swallow the verdict codes it exists to protect.

    A `not_ready` release still exits 2, and a successful run still exits 0 —
    otherwise the fix would trade one ambiguity for another.
    """
    not_ready = _run(
        "run",
        "--application",
        "a",
        "--repository",
        "o/r",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--output-dir",
        str(tmp_path / "empty"),
    )
    assert not_ready.returncode == 2

    ok = _run(
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
        str(sample_release_root / "artifacts"),
        "--attestations-dir",
        str(sample_release_root / "attestations"),
        "--output-dir",
        str(tmp_path / "full"),
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr


@pytest.mark.integration
def test_help_and_version_still_exit_zero() -> None:
    """Deliberate exits raise SystemExit, which the guard must not intercept."""
    assert _run("--version").returncode == 0
    assert _run("--help").returncode == 0
