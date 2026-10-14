"""Unit tests for the `sdlc-evidence doctor` command."""

from __future__ import annotations

import json
import os
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
    assert "no CLI command" in gl[2]
    # Optional checks must never flip to failed.
    assert gh[1] is True
    assert gl[1] is True


def test_doctor_absent_github_token_says_calls_go_out_unauthenticated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `run --pull-request` still calls the API without a token, so doctor
    # must not claim the collector is skipped.
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    results = _doctor_checks()
    gh = next(r for r in results if r[0] == "GitHub token (optional)")
    assert gh[1] is True
    assert "unauthenticated" in gh[2]
    assert "skip" not in gh[2]


def test_doctor_present_gitlab_token_is_not_claimed_as_used_by_the_cli(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No CLI command reads GITLAB_TOKEN, so a set token must not be reported
    # as "will be used".
    monkeypatch.setenv("GITLAB_TOKEN", "glpat_fake_for_test_only")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake_for_test_only")
    results = _doctor_checks()
    gl = next(r for r in results if r[0] == "GitLab token (optional)")
    gh = next(r for r in results if r[0] == "GitHub token (optional)")
    assert gl[1] is True
    assert gl[2].startswith("present")
    assert "no CLI command" in gl[2]
    assert "will be used" not in gl[2]
    assert gh[2].startswith("present")
    assert "--pull-request" in gh[2]


# A cwd the user cannot write to hung `doctor` forever at 100% CPU on Windows.
# The check used `tempfile.NamedTemporaryFile`, and CPython's tempfile treats a
# PermissionError in a directory it believes writable as a name collision on
# Windows and retries with a new name - up to TMP_MAX, which is 2**31 - 1
# there. The probe must make one attempt and report what it got.


def _deny_writes_in(directory: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make every ``os.open`` inside ``directory`` fail; return the attempts."""
    real_open = os.open
    attempts: list[str] = []

    def fake_open(path: str | os.PathLike[str], flags: int, *args: int, **kwargs: int) -> int:
        target = Path(os.fspath(path))
        if target.parent.exists() and os.path.samefile(target.parent, directory):
            attempts.append(str(target))
            if len(attempts) > 3:
                # Fail instead of looping: this is the retry the fix removes.
                raise AssertionError(f"write probe retried {len(attempts)} times")
            raise PermissionError(13, "Permission denied", str(target))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake_open)
    return attempts


def test_doctor_write_check_fails_once_on_a_read_only_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    attempts = _deny_writes_in(tmp_path, monkeypatch)

    results = _doctor_checks()

    write = next(r for r in results if r[0] == "Write permission in cwd")
    assert write[1] is False
    assert "PermissionError" in write[2]
    assert len(attempts) == 1, attempts
    assert list(tmp_path.iterdir()) == []


def test_doctor_cli_exits_one_on_a_read_only_cwd(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    _deny_writes_in(tmp_path, monkeypatch)

    result = CliRunner().invoke(app, ["doctor", "--json"])

    assert result.exception is None or isinstance(result.exception, SystemExit), result.exception
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    failed = [item["check"] for item in payload["checks"] if not item["ok"]]
    assert failed == ["Write permission in cwd"]


def test_doctor_write_check_leaves_no_probe_file_behind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    write = next(r for r in _doctor_checks() if r[0] == "Write permission in cwd")
    assert write[1] is True
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="POSIX permission bits; root ignores them",
)
def test_doctor_write_check_reports_a_real_read_only_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        monkeypatch.chdir(locked)
        write = next(r for r in _doctor_checks() if r[0] == "Write permission in cwd")
    finally:
        locked.chmod(0o700)
    assert write[1] is False
    assert "PermissionError" in write[2]
