"""Unit tests for the `sdlc-evidence doctor` command."""

from __future__ import annotations

import json
import sys
from collections import namedtuple
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import _doctor_checks, app

# `sys.version_info` is a `version_info` namedtuple-like that cannot be
# reconstructed directly, but `_doctor_checks` only compares it against
# `(3, 12)` and reads `.major` / `.minor` / `.micro`. A namedtuple with
# the same fields is enough for the test surface.
FakeVersionInfo = namedtuple("FakeVersionInfo", "major minor micro releaselevel serial")


def test_doctor_checks_all_pass_in_test_env() -> None:
    # Pytest runs inside the project's own virtualenv, so every
    # required check should pass without intervention. Optional checks
    # (tokens, cosign) report status but never fail.
    results = _doctor_checks()
    failed = [(label, detail) for label, ok, detail in results if not ok]
    assert failed == [], f"unexpected doctor failures: {failed}"

    labels = [label for label, _, _ in results]
    assert "Python version" in labels
    assert "Import: pydantic" in labels
    assert "Schema export" in labels
    assert "Write permission in cwd" in labels


def test_doctor_cli_table_exits_zero_on_healthy_env() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "All required checks passed." in result.output


def test_doctor_cli_json_emits_machine_readable_output() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["failed"] == 0
    assert isinstance(payload["checks"], list)
    assert all({"check", "ok", "detail"} <= set(item) for item in payload["checks"])


def _fake_version_info(major: int, minor: int, micro: int) -> FakeVersionInfo:
    return FakeVersionInfo(major, minor, micro, "final", 0)


def test_doctor_reports_python_version_below_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "version_info", _fake_version_info(3, 11, 9))
    results = _doctor_checks()
    py_check = next(r for r in results if r[0] == "Python version")
    assert py_check[1] is False
    assert "requires >=3.12" in py_check[2]


def test_doctor_cli_exits_one_when_required_check_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "version_info", _fake_version_info(3, 11, 9))
    runner = CliRunner()
    # Run from a writable cwd so only the Python check fails.
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1, result.output
    assert "required check(s) failed" in result.output


def test_doctor_optional_token_status_reflects_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_for_test_only")
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    results = _doctor_checks()
    gh = next(r for r in results if r[0] == "GitHub token (optional)")
    gl = next(r for r in results if r[0] == "GitLab token (optional)")
    assert "present" in gh[2]
    assert "absent" in gl[2]
    # Optional checks must never flip to failed.
    assert gh[1] is True
    assert gl[1] is True
