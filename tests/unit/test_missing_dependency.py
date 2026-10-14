"""A missing runtime dependency must not crash the CLI with a raw traceback.

Found by an end-user validation of 4.1.0: with ``defusedxml`` uninstalled,
every command, ``doctor`` included, died at import time with a Python
traceback, so ``doctor``'s ``Import:`` rows could never report the very
failure they exist for. A missing dependency now prints one line naming the
package (exit 3), and ``doctor`` still prints its checks with the failed
``Import:`` row (exit 1).

The subprocess tests block a module with ``sys.modules[name] = None``, which
makes ``import name`` raise ``ModuleNotFoundError`` exactly as an uninstalled
package does, and exercise both entry points: the ``sdlc-evidence`` console
script (``from evidence_collector.cli.main import main``) and
``python -m evidence_collector.cli.main``.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from evidence_collector.cli import _preflight
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR

_ENTRY_POINTS = {
    "console-script": "from evidence_collector.cli.main import main; main()",
    "python -m": (
        "import runpy; runpy.run_module('evidence_collector.cli.main', "
        "run_name='__main__', alter_sys=True)"
    ),
}


def _run_without(
    module: str, *args: str, entry: str = "console-script"
) -> subprocess.CompletedProcess[str]:
    code = (
        f"import sys; sys.modules[{module!r}] = None; "
        f"sys.argv = ['sdlc-evidence', *{list(args)!r}]; " + _ENTRY_POINTS[entry]
    )
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.mark.parametrize("entry", sorted(_ENTRY_POINTS))
def test_missing_dependency_exits_3_with_one_line(entry: str) -> None:
    result = _run_without("defusedxml", "controls", entry=entry)

    assert result.returncode == EXIT_INPUT_ERROR, result.stderr
    assert "Traceback" not in result.stderr + result.stdout
    lines = result.stderr.strip().splitlines()
    assert len(lines) == 1, result.stderr
    assert "'defusedxml'" in lines[0]
    assert "pip install --force-reinstall secure-sdlc-evidence-collector" in lines[0]


def test_missing_dependency_names_the_distribution_not_the_import() -> None:
    result = _run_without("yaml", "controls")

    assert result.returncode == EXIT_INPUT_ERROR, result.stderr
    assert "'PyYAML'" in result.stderr


def test_missing_dependency_keeps_the_ndjson_contract() -> None:
    result = _run_without("defusedxml", "--json-logs", "controls")

    assert result.returncode == EXIT_INPUT_ERROR, result.stderr
    event = json.loads(result.stdout)
    assert event["event"] == "command_failed"
    assert event["error_type"] == "ModuleNotFoundError"
    assert "'defusedxml'" in event["reason"]


@pytest.mark.parametrize("entry", sorted(_ENTRY_POINTS))
def test_doctor_reports_the_missing_dependency_as_json(entry: str) -> None:
    result = _run_without("defusedxml", "doctor", "--json", entry=entry)

    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stderr
    payload = json.loads(result.stdout)
    rows = {item["check"]: item for item in payload["checks"]}
    assert rows["Import: defusedxml"]["ok"] is False
    assert rows["Import: pydantic"]["ok"] is True
    assert rows["Python version"]["ok"] is True
    assert payload["failed"] == 1


def test_doctor_reports_the_missing_dependency_as_a_table() -> None:
    result = _run_without("defusedxml", "doctor")

    assert result.returncode == 1, result.stderr
    assert "Traceback" not in result.stderr
    row = next(line for line in result.stdout.splitlines() if line.startswith("Import: defusedxml"))
    assert "FAIL" in row
    assert "1 required check(s) failed." in result.stdout


def test_doctor_reports_the_missing_dependency_as_ndjson() -> None:
    result = _run_without("defusedxml", "--json-logs", "doctor")

    assert result.returncode == 1, result.stderr
    event = json.loads(result.stdout)
    assert event["event"] == "doctor_checked"
    assert event["failed"] == 1


def test_doctor_reports_a_missing_dependency_it_does_not_import_by_name() -> None:
    # `markupsafe` is pulled in by jinja2; doctor's own list does not name it,
    # yet blocking it breaks `import jinja2`, which doctor does report.
    result = _run_without("markupsafe", "doctor", "--json")

    assert result.returncode == 1, result.stderr
    rows = {item["check"]: item for item in json.loads(result.stdout)["checks"]}
    assert rows["Import: jinja2"]["ok"] is False


# In-process checks of the guard itself, so its branches count toward coverage.


def _raise(exc: BaseException) -> None:
    # A call keeps the assertions after each ``with`` block reachable for
    # static analysis, which does not know the guard turns this into SystemExit.
    raise exc


def test_guard_exit_code_matches_the_cli_taxonomy() -> None:
    assert _preflight.EXIT_INPUT_ERROR == EXIT_INPUT_ERROR


def test_guard_converts_a_missing_dependency(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["sdlc-evidence", "controls"])
    monkeypatch.delenv("SDLC_JSON_LOGS", raising=False)
    with pytest.raises(SystemExit) as excinfo, _preflight.exit_on_missing_dependency():
        _raise(ModuleNotFoundError("No module named 'defusedxml'", name="defusedxml.ElementTree"))
    assert excinfo.value.code == EXIT_INPUT_ERROR
    assert "'defusedxml'" in capsys.readouterr().err


def test_guard_leaves_doctor_help_to_the_one_line_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["sdlc-evidence", "doctor", "--help"])
    with pytest.raises(SystemExit) as excinfo, _preflight.exit_on_missing_dependency():
        _raise(ModuleNotFoundError("No module named 'rich'", name="rich"))
    assert excinfo.value.code == EXIT_INPUT_ERROR
    assert "'rich'" in capsys.readouterr().err


def test_guard_runs_plain_doctor_for_an_unlisted_module(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Every listed import is healthy here, so the guard adds the row itself.
    monkeypatch.setattr(sys, "argv", ["sdlc-evidence", "-v", "doctor"])
    monkeypatch.delenv("SDLC_JSON_LOGS", raising=False)
    with pytest.raises(SystemExit) as excinfo, _preflight.exit_on_missing_dependency():
        _raise(ModuleNotFoundError("No module named 'shellingham'", name="shellingham"))
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Import: shellingham" in out
    assert "FAIL" in out


@pytest.mark.parametrize("name", ["evidence_collector.cli.missing", None])
def test_guard_reraises_what_is_not_a_third_party_dependency(name: str | None) -> None:
    with pytest.raises(ModuleNotFoundError), _preflight.exit_on_missing_dependency():
        raise ModuleNotFoundError("boom", name=name)


def test_guard_reports_the_missing_module_next_to_unrelated_failures(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # An unwritable cwd used to hide the module that actually stopped the CLI.
    monkeypatch.setattr(sys, "argv", ["sdlc-evidence", "doctor"])
    monkeypatch.delenv("SDLC_JSON_LOGS", raising=False)
    monkeypatch.setattr(_preflight, "_cwd_write_check", lambda: (False, "PermissionError"))
    with pytest.raises(SystemExit) as excinfo, _preflight.exit_on_missing_dependency():
        _raise(ModuleNotFoundError("No module named 'shellingham'", name="shellingham"))
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Write permission in cwd" in out
    assert "Import: shellingham" in out


@pytest.mark.parametrize(
    "extra", [[], ["--json"], ["--json-logs"]], ids=["table", "json", "ndjson"]
)
def test_plain_doctor_reconfigures_a_non_utf8_console(
    monkeypatch: pytest.MonkeyPatch, extra: list[str]
) -> None:
    # The guard exits before main() switches the streams to UTF-8, so the
    # fallback must do it itself or a non-ASCII detail crashes on cp1252.
    import io

    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", console)
    monkeypatch.setattr(sys, "argv", ["sdlc-evidence", "doctor", *extra])
    monkeypatch.delenv("SDLC_JSON_LOGS", raising=False)
    monkeypatch.setattr(_preflight, "_cwd_write_check", lambda: (False, "denied: C:/proj/ação→é"))
    with pytest.raises(SystemExit) as excinfo, _preflight.exit_on_missing_dependency():
        _raise(ModuleNotFoundError("No module named 'shellingham'", name="shellingham"))
    console.flush()
    assert excinfo.value.code == 1
    assert "shellingham" in raw.getvalue().decode("utf-8")
