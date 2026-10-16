"""CLI messages and edge cases found in an end-user validation of 4.1.4.

Each test pins one behaviour a user hit: a hint pointing at a rejected flag, an
error that did not say which file failed, a directory accepted where a file was
expected, help text written for the maintainer, and log lines that broke the
NDJSON stream.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_MODULE = "evidence_collector.cli.main"
_IDENTITY = (
    "--application",
    "a",
    "--repository",
    "o/r",
    "--release-id",
    "1",
    "--commit-sha",
    "abcdef1234567890",
)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", _MODULE, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env={**__import__("os").environ, "COLUMNS": "200"},
    )


def _waiver(directory: Path, name: str, exception_id: str) -> None:
    (directory / name).write_text(
        f"exception_id: {exception_id}\n"
        "control_id: SSDF-PW.7\n"
        "approver: security-lead\n"
        "approved_at: 2026-01-01T00:00:00Z\n"
        "expires_at: 2099-01-01T00:00:00Z\n"
        "justification: test waiver for the CLI\n",
        encoding="utf-8",
    )


@pytest.mark.integration
def test_the_verbose_hint_names_the_global_position() -> None:
    result = _run("controls", "--catalog", "definitely-not-here.yaml")
    assert result.returncode == 3
    assert "sdlc-evidence --verbose <command>" in result.stderr


@pytest.mark.integration
def test_the_verbose_hint_is_omitted_when_verbose_is_already_on() -> None:
    result = _run("--verbose", "controls", "--catalog", "definitely-not-here.yaml")
    assert result.returncode == 3
    assert "Re-run as" not in result.stderr


@pytest.mark.integration
def test_compare_names_the_bundle_it_could_not_read(
    tmp_path: Path, sample_release_root: Path
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("", encoding="utf-8")
    _run(
        "run",
        *_IDENTITY,
        "--attestations-dir",
        str(sample_release_root / "attestations"),
        "--output-dir",
        str(tmp_path / "out"),
    )
    good = tmp_path / "out" / "bundle.json"
    assert good.is_file()
    # The second file is the broken one: the message must not name the first.
    result = _run("compare", str(good), str(broken))
    assert result.returncode == 3
    assert "broken.json" in result.stderr


@pytest.mark.integration
def test_exceptions_validate_points_a_directory_to_list(tmp_path: Path) -> None:
    result = _run("exceptions", "validate", str(tmp_path))
    assert result.returncode == 3
    assert "is a directory" in result.stderr
    assert "exceptions list" in result.stderr


@pytest.mark.integration
def test_exceptions_list_fails_on_an_unparseable_file(tmp_path: Path) -> None:
    _waiver(tmp_path, "good.yaml", "EXC-1")
    (tmp_path / "bad.yaml").write_text("exception_id: [\n", encoding="utf-8")
    result = _run("exceptions", "list", str(tmp_path))
    assert result.returncode == 3
    assert "1 unparseable" in result.stdout


@pytest.mark.integration
def test_exceptions_list_flags_a_duplicate_id(tmp_path: Path) -> None:
    _waiver(tmp_path, "a.yaml", "EXC-1")
    _waiver(tmp_path, "b.yaml", "EXC-1")
    result = _run("--json-logs", "exceptions", "list", str(tmp_path))
    assert result.returncode == 3
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert any(e["event"] == "exception_duplicate" for e in events)
    summary = next(e for e in events if e["event"] == "exceptions_summary")
    assert summary["duplicate_ids"] == 1


@pytest.mark.integration
def test_exceptions_list_of_valid_waivers_still_exits_zero(tmp_path: Path) -> None:
    _waiver(tmp_path, "a.yaml", "EXC-1")
    assert _run("exceptions", "list", str(tmp_path)).returncode == 0


@pytest.mark.integration
@pytest.mark.parametrize(
    "command",
    [("oscal",), ("schema",)],
    ids=["oscal", "schema"],
)
def test_an_output_path_that_is_a_directory_is_named(
    tmp_path: Path, command: tuple[str, ...]
) -> None:
    result = _run(*command, "--output", str(tmp_path))
    assert result.returncode == 3
    assert "Output path exists as a directory" in result.stderr


@pytest.mark.integration
def test_evaluate_rejects_a_directory_as_the_evidence_file(tmp_path: Path) -> None:
    result = _run("evaluate", "--evidence", str(tmp_path), *_IDENTITY)
    assert result.returncode == 3
    assert "is a directory" in result.stderr


@pytest.mark.integration
def test_run_warns_when_the_artifact_root_does_not_contain_the_inputs(
    tmp_path: Path, sample_release_root: Path
) -> None:
    result = _run(
        "run",
        *_IDENTITY,
        "--attestations-dir",
        str(sample_release_root.resolve() / "attestations"),
        "--artifact-root",
        str(tmp_path / "elsewhere"),
        "--output-dir",
        str(tmp_path / "out"),
    )
    assert "does not exist" in result.stdout
    assert "does not contain" in result.stdout


@pytest.mark.integration
@pytest.mark.parametrize(
    "command",
    [
        ("collect",),
        ("exceptions", "validate"),
        ("exceptions", "list"),
        ("oscal",),
        ("verify",),
    ],
    ids=lambda c: " ".join(c),
)
def test_help_text_carries_no_maintainer_notes(command: tuple[str, ...]) -> None:
    text = _run(*command, "--help").stdout
    for leak in ("``", "used to", "EXIT_INPUT_ERROR", "src/evidence_collector", "first-class"):
        assert leak not in text, leak


@pytest.mark.integration
def test_fail_on_help_says_ready_behaves_like_conditional() -> None:
    text = " ".join(_run("run", "--help").stdout.split())
    assert "'ready' is accepted and behaves like conditional" in text


@pytest.mark.integration
def test_statement_help_says_slsa_provenance_keeps_the_bundle_as_predicate() -> None:
    text = " ".join(_run("statement", "--help").stdout.split())
    assert "without buildDefinition or runDetails" in text


@pytest.mark.integration
def test_json_logs_keep_stderr_as_json_lines(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    # Two runs, one of them unsupported: the collector logs a warning for it.
    (artifacts / "mixed.sarif").write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {"tool": {"driver": {"name": "Semgrep", "rules": []}}, "results": []},
                    {"tool": {"driver": {"name": "NotAScanner", "rules": []}}, "results": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    result = _run(
        "--json-logs",
        "collect",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--artifacts-dir",
        str(artifacts),
        "--output",
        str(tmp_path / "evidence.json"),
    )
    for line in result.stderr.splitlines():
        if line.strip():
            assert json.loads(line)["event"] == "log"


@pytest.mark.integration
def test_a_failed_input_is_reported_once_in_human_mode(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "broken.sarif").write_text("{", encoding="utf-8")
    result = _run(
        "collect",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--artifacts-dir",
        str(artifacts),
        "--output",
        str(tmp_path / "evidence.json"),
    )
    combined = result.stdout + result.stderr
    assert "Failed to ingest" not in combined
    assert "broken.sarif" in combined
