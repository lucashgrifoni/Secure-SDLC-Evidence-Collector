"""The terminal layout of `run`, `compare` and `doctor`.

A colour terminal gets the verdict block, the diff with arrows and the doctor
checklist. A pipe, a file, `NO_COLOR`, `TERM=dumb` and `--json-logs` keep the
tables these commands always printed: scripts and CI logs read them. A console
that cannot show the bar and arrow characters gets ASCII stand-ins.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from evidence_collector.application.compare import ControlDelta, compare_bundles, load_bundle
from evidence_collector.application.orchestrator import BundleBuildResult
from evidence_collector.cli import _render, _state
from evidence_collector.cli._compare_view import _control_row, render_compare_view
from evidence_collector.cli._doctor_view import render_doctor_view
from evidence_collector.cli._preflight import CheckResult, doctor_checks
from evidence_collector.cli._run_view import render_run_view
from evidence_collector.cli._terminal import (
    ASCII_GLYPHS,
    UNICODE_GLYPHS,
    glyphs_for,
    uses_layout,
)
from evidence_collector.cli._theme import install
from evidence_collector.cli.commands import compare as compare_cmd
from evidence_collector.cli.commands import doctor as doctor_cmd
from evidence_collector.cli.commands import run as run_cmd
from evidence_collector.cli.main import app
from evidence_collector.domain.enums import ControlEvaluationStatus

SAMPLE = Path(__file__).resolve().parents[2] / "examples/sample_release"
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"
RUN = [
    "run",
    "--application",
    "payments-api",
    "--repository",
    "acme/payments-api",
    "--release-id",
    "2026.04.10",
    "--commit-sha",
    COMMIT,
    "--artifacts-dir",
    str(SAMPLE / "artifacts"),
]
DASH = UNICODE_GLYPHS.dash
LAYOUT_MARKERS = ("Exit ", "Wrote ", "Required", "improved ·")


def _terminal(**overrides: object) -> Console:
    options: dict[str, object] = {
        "file": io.StringIO(),
        "record": True,
        "force_terminal": True,
        "color_system": "truecolor",
        "width": 120,
        "legacy_windows": False,
    }
    options.update(overrides)
    return install(Console(**options))  # type: ignore[arg-type]


def _text(console: Console) -> str:
    return console.export_text()


@pytest.fixture(scope="module")
def bundles(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """A not_ready and a ready bundle of the sample release."""
    root = tmp_path_factory.mktemp("layout")
    runner = CliRunner()
    not_ready = runner.invoke(app, [*RUN, "--output-dir", str(root / "not_ready")])
    ready = runner.invoke(
        app,
        [
            *RUN,
            "--attestations-dir",
            str(SAMPLE / "attestations"),
            "--exceptions-dir",
            str(SAMPLE / "exceptions"),
            "--output-dir",
            str(root / "ready"),
        ],
    )
    assert (not_ready.exit_code, ready.exit_code) == (2, 0)
    return {"not_ready": root / "not_ready", "ready": root / "ready"}


def _result(directory: Path) -> BundleBuildResult:
    return BundleBuildResult(
        bundle=load_bundle(directory / "bundle.json"),
        json_path=directory / "bundle.json",
        markdown_path=directory / "report.md",
        html_path=directory / "summary.html",
    )


@pytest.fixture
def layout_console(monkeypatch: pytest.MonkeyPatch) -> Iterator[Console]:
    """Point every command at a recording console forced to a colour terminal."""
    console = _terminal()
    for module in (run_cmd, compare_cmd, doctor_cmd, _render, _state):
        monkeypatch.setattr(module, "console", console)
    yield console


# --- when the layout applies -------------------------------------------------


@pytest.mark.parametrize("color_system", ["truecolor", "256", "standard", "windows"])
def test_a_colour_terminal_gets_the_layout(color_system: str) -> None:
    assert uses_layout(_terminal(color_system=color_system))


@pytest.mark.parametrize(
    "console",
    [
        pytest.param(_terminal(no_color=True), id="no_color"),
        pytest.param(_terminal(_environ={"NO_COLOR": "1"}), id="NO_COLOR"),
        pytest.param(_terminal(force_terminal=False, color_system="auto"), id="pipe"),
        pytest.param(
            _terminal(color_system="auto", _environ={"TERM": "dumb"}),
            id="TERM=dumb",
        ),
    ],
)
def test_no_colour_a_pipe_and_a_dumb_terminal_keep_the_tables(console: Console) -> None:
    assert not uses_layout(console)


def test_json_logs_keep_ndjson(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_state, "_JSON_LOGS_ENABLED", True)
    assert not uses_layout(_terminal())


# --- run ---------------------------------------------------------------------


@pytest.mark.parametrize("color_system", ["truecolor", "256"])
def test_run_not_ready_shows_verdict_measures_missing_evidence_and_exit(
    bundles: dict[str, Path], color_system: str
) -> None:
    console = _terminal(color_system=color_system)
    render_run_view(console, _result(bundles["not_ready"]), exit_code=2)
    lines = _text(console).splitlines()
    assert lines[0].startswith(" NOT READY   payments-api 2026.04.10 · commit abcdef1")
    assert lines[1] == "A critical control lacks required evidence."
    text = "\n".join(lines)
    assert "Coverage   █████████░░░░░░░░░░░   47/100" in text
    assert "Strength   ████████████████████  100/100  of the 7 controls with evidence" in text
    assert "Controls   5 met · 2 partial · 6 missing  of 13" in text
    assert "Missing critical evidence (each one blocks the release)" in text
    for control_id, kind in (
        ("ORG-CODE-REVIEW", "code_review"),
        ("ORG-RELEASE-APPROVAL", "release_approval"),
        ("ORG-REL-ROLLBACK", "rollback_plan"),
        ("SSDF-PS.2", "artifact_signature"),
    ):
        assert any(line.split() == ["✗", control_id, kind] for line in lines), (
            f"{control_id} {kind} on its own line"
        )
    assert "Next       add the 4 missing items above and run again" in text
    assert "examples/sample_release/attestations" in text
    assert f"Wrote      {bundles['not_ready'] / 'summary.html'}  open this one first" in text
    assert lines[-1] == "  Exit       2"


def test_run_ready_explains_where_the_strength_comes_from(bundles: dict[str, Path]) -> None:
    console = _terminal()
    render_run_view(console, _result(bundles["ready"]), exit_code=0)
    text = _text(console)
    assert text.startswith(" READY   payments-api 2026.04.10")
    assert "Every control is met, waived or not applicable." in text
    assert "59/100  5 tool-backed, 8 attested by hand" in text
    assert "Controls   13 met  of 13" in text
    assert "Missing" not in text
    assert "Next" not in text
    assert text.rstrip().endswith("Exit       0")


def test_run_paints_the_verdict_as_a_badge(bundles: dict[str, Path]) -> None:
    console = _terminal()
    render_run_view(console, _result(bundles["not_ready"]), exit_code=2)
    html = console.export_html()
    assert "background-color: #ef5c5c" in html, "the not_ready fill of the theme"


def test_run_command_prints_the_layout_in_a_terminal_and_keeps_the_exit_code(
    layout_console: Console, tmp_path: Path
) -> None:
    result = CliRunner().invoke(app, [*RUN, "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    text = _text(layout_console)
    assert "Release readiness summary" not in text
    assert text.rstrip().endswith("Exit       2")


def test_run_command_with_fail_on_conditional_still_exits_zero_when_ready(
    layout_console: Console, tmp_path: Path
) -> None:
    args = [
        *RUN,
        "--attestations-dir",
        str(SAMPLE / "attestations"),
        "--exceptions-dir",
        str(SAMPLE / "exceptions"),
        "--output-dir",
        str(tmp_path),
        "--fail-on",
        "conditional",
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0
    assert _text(layout_console).rstrip().endswith("Exit       0")


def test_run_to_a_pipe_prints_the_table_as_before(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, [*RUN, "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "Release readiness summary" in result.output
    assert "coverage=47 confidence=100" in result.output
    assert not any(marker in result.output for marker in LAYOUT_MARKERS)


# --- compare -----------------------------------------------------------------


def test_compare_shows_direction_deltas_and_folds_unchanged_controls(
    bundles: dict[str, Path],
) -> None:
    before = load_bundle(bundles["not_ready"] / "bundle.json")
    after = load_bundle(bundles["ready"] / "bundle.json")
    console = _terminal()
    render_compare_view(console, before, after, compare_bundles(before, after))
    lines = _text(console).splitlines()
    assert lines[0].split() == [
        "payments-api",
        "2026.04.10",
        "not_ready",
        "→",
        "ready",
        "▲",
        "improved",
    ]
    text = "\n".join(lines)
    assert "Coverage    47 → 100   +53" in text
    assert "Strength   100 →  59   -41  controls attested by hand 0 → 8" in text
    assert "Controls   8 improved · 0 regressed · 5 unchanged" in text
    assert "▲ ORG-CODE-REVIEW        missing → met" in text
    assert "▲ SAMM-IMPL-SB-2         partial → met" in text
    assert lines[-1].strip() == (
        "= ORG-SECRETS-SCAN, SAMM-VERIF-ST-1, SSDF-PW.4, SSDF-PW.7, SSDF-PW.8"
    )


def test_compare_marks_a_regression(bundles: dict[str, Path]) -> None:
    before = load_bundle(bundles["ready"] / "bundle.json")
    after = load_bundle(bundles["not_ready"] / "bundle.json")
    console = _terminal()
    render_compare_view(console, before, after, compare_bundles(before, after))
    text = _text(console)
    assert "ready  →  not_ready    ▼ regressed" in text
    assert "0 improved · 8 regressed · 5 unchanged" in text
    assert "▼ ORG-CODE-REVIEW        met → missing" in text


def test_compare_shows_an_added_control_as_a_neutral_change() -> None:
    delta = ControlDelta("NEW-1", before=None, after=ControlEvaluationStatus.MET)
    row = _control_row(delta, set(), set(), set(), width=8, glyphs=UNICODE_GLYPHS)
    assert row == "    [muted]·[/muted] NEW-1   absent → met"


def test_compare_command_in_a_terminal_keeps_json_and_exit_code(
    layout_console: Console, bundles: dict[str, Path]
) -> None:
    paths = [str(bundles["not_ready"] / "bundle.json"), str(bundles["ready"] / "bundle.json")]
    table = CliRunner().invoke(app, ["compare", *paths])
    assert table.exit_code == 0
    assert "Bundle diff" not in _text(layout_console)
    as_json = CliRunner().invoke(app, ["compare", *paths, "--format", "json"])
    assert as_json.exit_code == 0
    assert '"coverage_delta": 53' in _text(layout_console)


def test_compare_to_a_pipe_prints_the_tables_as_before(bundles: dict[str, Path]) -> None:
    paths = [str(bundles["not_ready"] / "bundle.json"), str(bundles["ready"] / "bundle.json")]
    result = CliRunner().invoke(app, ["compare", *paths])
    assert result.exit_code == 0
    assert "Bundle diff" in result.output
    assert "Control-level diff" in result.output
    assert not any(marker in result.output for marker in LAYOUT_MARKERS)


# --- doctor ------------------------------------------------------------------

HEALTHY: list[CheckResult] = [
    ("Python version", True, "3.12.10 (>=3.12)"),
    ("Import: typer", True, "ok"),
    ("Import: rich", True, "ok"),
    ("GitHub token (optional)", True, "absent (run --pull-request/--workflow-run ...)"),
    ("GitLab token (optional)", True, "absent (only read by the GitLabCollector library API)"),
    ("Schema export", True, "EvidenceBundle.model_json_schema() ok"),
    ("Write permission in cwd", True, "/work"),
    ("cosign (optional)", True, "/usr/bin/cosign"),
]


def test_doctor_separates_required_and_optional_and_dashes_what_is_not_set() -> None:
    console = _terminal()
    render_doctor_view(console, HEALTHY)
    lines = [line.rstrip() for line in _text(console).splitlines()]
    assert lines[2:7] == [
        "  Required",
        "    ✓ Python             3.12.10 (needs 3.12 or newer)",
        "    ✓ Libraries          typer, rich",
        "    ✓ Schema export      ok",
        "    ✓ Write permission   current folder",
    ]
    assert "  Optional" in lines
    assert any(line.startswith(f"    {DASH} GitHub token       not set") for line in lines)
    assert f"    {DASH} GitLab token       not set · only the library API reads it" in lines
    assert "    ✓ cosign             found" in lines
    assert lines[-1] == "  All required checks passed. 2 optional items are not set."


def test_doctor_names_a_missing_library_and_counts_the_failure() -> None:
    results = [*HEALTHY]
    results[2] = ("Import: rich", False, "No module named 'rich'")
    console = _terminal()
    render_doctor_view(console, results)
    lines = [line.rstrip() for line in _text(console).splitlines()]
    assert "    ✗ Library            rich: No module named 'rich'" in lines
    assert lines[-1] == "  1 required check(s) failed."


def test_doctor_reads_the_wording_doctor_checks_uses_for_an_unset_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GITLAB_TOKEN", "x")
    console = _terminal()
    render_doctor_view(console, doctor_checks())
    text = _text(console)
    assert f"{DASH} GitHub token       not set" in text
    assert "✓ GitLab token       set" in text


def test_doctor_command_in_a_terminal_keeps_json_and_exit_code(layout_console: Console) -> None:
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Required" in _text(layout_console)
    as_json = CliRunner().invoke(app, ["doctor", "--json"])
    assert as_json.exit_code == 0
    assert as_json.output.lstrip().startswith("{")


def test_doctor_to_a_pipe_prints_the_table_as_before() -> None:
    result = CliRunner().invoke(app, ["doctor"])
    assert "┃ Check" in result.output or "│ Check" in result.output
    assert not any(marker in result.output for marker in LAYOUT_MARKERS)


# --- consoles that cannot show the characters --------------------------------


def test_legacy_windows_and_non_utf8_consoles_get_ascii() -> None:
    assert glyphs_for(_terminal(legacy_windows=True)) is ASCII_GLYPHS
    cp1252 = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    assert glyphs_for(_terminal(file=cp1252)) is ASCII_GLYPHS
    assert glyphs_for(_terminal()) is UNICODE_GLYPHS


def test_a_cp1252_console_renders_every_view_without_an_encoding_error(
    bundles: dict[str, Path],
) -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    console = _terminal(file=stream, color_system="windows")
    before = load_bundle(bundles["not_ready"] / "bundle.json")
    after = load_bundle(bundles["ready"] / "bundle.json")
    render_run_view(console, _result(bundles["not_ready"]), exit_code=2)
    render_compare_view(console, before, after, compare_bundles(before, after))
    render_doctor_view(console, HEALTHY)
    stream.flush()
    text = _text(console)
    assert text.isascii(), sorted({c for c in text if not c.isascii()})
    assert "#########..........." in text
    assert "47 -> 100" in text
