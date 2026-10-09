"""Text from an input file must reach the terminal verbatim, never as Rich markup.

Collection warnings, parser messages and waiver fields were interpolated into
strings printed through Rich's markup parser. A closing tag with no opener in a
scanner-supplied name (`[/x]`) raised MarkupError, so `run` exited 3 instead of
returning its verdict; anything that looked like an opening tag (`[temporary]`)
was silently swallowed, so the operator read a different approver than the one
on file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app

# Longer than the normalizer's cap, so the record fails validation and the
# pydantic message (which quotes the value) becomes a collection warning.
_HOSTILE_DRIVER = "[/x]" + "A" * 120


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _artifacts(tmp_path: Path) -> Path:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": _HOSTILE_DRIVER, "rules": []}}, "results": []}],
    }
    (artifacts / "scan.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    return artifacts


@pytest.mark.integration
def test_run_prints_a_markup_like_collection_warning_and_returns_its_verdict(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--application",
            "a",
            "--repository",
            "o/r",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(_artifacts(tmp_path)),
            "--output-dir",
            str(tmp_path / "out"),
            "--fail-on",
            "not_ready",
        ],
    )
    assert isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 2, result.output
    assert "[/x]AAAA" in result.output


@pytest.mark.integration
def test_collect_prints_a_markup_like_collection_warning_verbatim(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "collect",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(_artifacts(tmp_path)),
            "--output",
            str(tmp_path / "evidence.json"),
        ],
    )
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert result.exit_code == 0, result.output
    assert "[/x]AAAA" in result.output


def _waiver(directory: Path, name: str, exception_id: str, approver: str) -> Path:
    path = directory / name
    path.write_text(
        f"exception_id: {exception_id}\n"
        "control_id: SSDF-PW.1\n"
        f"approver: '{approver}'\n"
        "approved_at: '2026-04-10T10:00:00Z'\n"
        "expires_at: '2099-04-10T10:00:00Z'\n"
        "justification: A justification long enough to pass.\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.integration
def test_exceptions_validate_prints_waiver_fields_verbatim(
    runner: CliRunner, tmp_path: Path
) -> None:
    closing = _waiver(tmp_path, "a.yaml", "EXC-A", "ops [/x] lead")
    opening = _waiver(tmp_path, "b.yaml", "EXC-B", "ops [temporary] lead")

    result = runner.invoke(app, ["exceptions", "validate", str(closing), str(opening)])
    assert isinstance(result.exception, SystemExit | type(None)), repr(result.exception)
    assert result.exit_code == 0, result.output
    assert "ops [/x] lead" in result.output
    assert "ops [temporary] lead" in result.output


@pytest.mark.integration
def test_exceptions_list_prints_waiver_fields_verbatim(runner: CliRunner, tmp_path: Path) -> None:
    _waiver(tmp_path, "a.yaml", "EXC-A", "[/x]")
    _waiver(tmp_path, "b.yaml", "EXC-B", "[temporary]")

    result = runner.invoke(app, ["exceptions", "list", str(tmp_path)], env={"COLUMNS": "200"})
    assert isinstance(result.exception, SystemExit | type(None)), repr(result.exception)
    assert result.exit_code == 0, result.output
    assert "[/x]" in result.output
    assert "[temporary]" in result.output
    assert "2 active" in result.output
