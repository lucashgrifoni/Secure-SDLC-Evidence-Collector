"""The exit-code taxonomy the README promises, pinned per command.

README: "**Every failure that is not a release verdict exits `3`.** A missing
or malformed bundle, an unreadable catalog, … all of them, on every command"
and "`1` means `conditional` and nothing else".

3.0.0 unified the input-error code across the command bodies, but two routes
still escaped it:

* the five bundle-consuming commands declared their argument with Click's
  `exists=True`, so a missing file raised UsageError -> exit **2** before the
  body ever ran — 2 being the `not_ready` verdict code, which is exactly the
  collision the unification existed to remove;
* `exceptions validate` exited **1**, the `conditional` code, for a waiver
  file that does not exist.

A wrapper is supposed to branch on the code alone. These tests exist so it
can.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR, exit_code_for_status
from evidence_collector.cli.main import app
from evidence_collector.domain.enums import ReleaseStatus


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# Every command whose first argument is a bundle the user must supply.
_BUNDLE_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("verify",),
    ("vex",),
    ("guac",),
    ("statement",),
    ("enrich",),
    ("compare",),
)


@pytest.mark.integration
@pytest.mark.parametrize("command", _BUNDLE_COMMANDS, ids=lambda c: c[0])
def test_missing_input_file_exits_with_the_input_error_code(
    runner: CliRunner, tmp_path: Path, command: tuple[str, ...]
) -> None:
    missing = tmp_path / "does-not-exist.json"
    args = [*command, str(missing)]
    if command[0] == "compare":
        args.append(str(missing))
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_INPUT_ERROR, (
        f"{command[0]} exited {result.exit_code} for a missing file; "
        f"the README promises {EXIT_INPUT_ERROR}. Output:\n{result.output}"
    )


@pytest.mark.integration
@pytest.mark.parametrize("command", _BUNDLE_COMMANDS, ids=lambda c: c[0])
def test_malformed_input_file_exits_with_the_input_error_code(
    runner: CliRunner, tmp_path: Path, command: tuple[str, ...]
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    args = [*command, str(broken)]
    if command[0] == "compare":
        args.append(str(broken))
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_INPUT_ERROR, result.output


@pytest.mark.integration
def test_missing_waiver_file_does_not_claim_the_conditional_code(
    runner: CliRunner, tmp_path: Path
) -> None:
    result = runner.invoke(app, ["exceptions", "validate", str(tmp_path / "nope.yaml")])
    assert result.exit_code == EXIT_INPUT_ERROR, result.output
    assert result.exit_code != 1, "1 is reserved for the `conditional` verdict"


@pytest.mark.integration
def test_no_command_uses_the_verdict_codes_for_a_bad_input(
    runner: CliRunner, tmp_path: Path
) -> None:
    """The collision that mattered: 2 meant not_ready AND bad input at once."""
    missing = tmp_path / "gone.json"
    for command in _BUNDLE_COMMANDS:
        args = [*command, str(missing)]
        if command[0] == "compare":
            args.append(str(missing))
        code = runner.invoke(app, args).exit_code
        assert code not in (1, 2), (
            f"{command[0]} returned verdict code {code} for a missing input; "
            "a wrapper cannot tell that from a real release verdict"
        )


# ---------------------------------------------------------------------------
# A missing input directory is the documented exception to the taxonomy
#
# An end-user validation of 4.1.0 read "every failure that is not a release
# verdict exits 3" and expected `run --artifacts-dir nope/a` to exit 3; it
# exits with the verdict instead. That is deliberate and other documented
# flows depend on it: the Action passes a configured `exceptions-dir` through
# even when it is missing ("the collector reports the bad path in the
# collection warnings"), and the reusable workflow and the GitLab template pass
# `--artifacts-dir` unconditionally. Exiting 3 there would abort before any
# bundle is written. The README now states the exception; these tests pin it.
# ---------------------------------------------------------------------------


def _run_args(output_dir: Path, *extra: str) -> list[str]:
    return [
        "run",
        "--application",
        "a",
        "--repository",
        "o/r",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1",
        "--output-dir",
        str(output_dir),
        *extra,
    ]


def test_run_exits_input_error_when_no_input_directory_exists(
    runner: CliRunner, tmp_path: Path
) -> None:
    # Every directory passed is missing, so nothing could be read: that is an
    # input error (3), not a not_ready verdict, and no bundle is written.
    missing_artifacts = tmp_path / "nope" / "a"
    missing_attestations = tmp_path / "nope" / "b"
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        _run_args(
            out,
            "--artifacts-dir",
            str(missing_artifacts),
            "--attestations-dir",
            str(missing_attestations),
        ),
    )

    assert result.exit_code == EXIT_INPUT_ERROR, result.output
    assert not (out / "bundle.json").exists()
    assert "none of the input directories exist" in result.output
    assert str(missing_artifacts) in result.output


def test_a_partly_missing_input_set_stays_a_collection_error(
    runner: CliRunner, tmp_path: Path, sample_release_root: Path
) -> None:
    # One readable directory is enough to evaluate: the missing one is
    # recorded and the exit code is the verdict.
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        _run_args(
            out,
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(tmp_path / "missing-attestations"),
        ),
    )

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    status = ReleaseStatus(bundle["summary"]["release_status"])
    assert result.exit_code == exit_code_for_status(status), result.output
    assert result.exit_code != EXIT_INPUT_ERROR
    errors = {(Path(e["path"]).name, e["reason"]) for e in bundle["collection_errors"]}
    assert ("missing-attestations", "directory not found") in errors


def test_missing_exceptions_dir_keeps_the_verdict_of_the_evidence(
    runner: CliRunner, tmp_path: Path, sample_release_root: Path
) -> None:
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        _run_args(
            out,
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--exceptions-dir",
            str(tmp_path / "missing-waivers"),
        ),
    )

    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    status = ReleaseStatus(bundle["summary"]["release_status"])
    assert result.exit_code == exit_code_for_status(status), result.output
    assert result.exit_code != EXIT_INPUT_ERROR
    assert [Path(e["path"]).name for e in bundle["collection_errors"]] == ["missing-waivers"]


def test_files_passed_as_input_directories_stay_collection_errors(
    runner: CliRunner, tmp_path: Path
) -> None:
    # A shell glob can pass files where directories were expected. They exist,
    # so this is not the "nothing to read" case: the bundle is still written.
    stray = tmp_path / "scan.sarif"
    stray.write_text("{}", encoding="utf-8")
    out = tmp_path / "out"
    result = runner.invoke(app, _run_args(out, "--artifacts-dir", str(stray)))

    assert result.exit_code != EXIT_INPUT_ERROR, result.output
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert [Path(e["path"]).name for e in bundle["collection_errors"]] == ["scan.sarif"]


def test_the_no_input_error_lists_paths_relative_to_artifact_root(
    runner: CliRunner, tmp_path: Path
) -> None:
    # The error goes to CI logs: an absolute workspace path must not leak when
    # --artifact-root was set to avoid exactly that.
    root = tmp_path / "clientA-private-workspace"
    root.mkdir()
    out = tmp_path / "out"
    result = runner.invoke(
        app,
        _run_args(
            out,
            "--artifacts-dir",
            str(root / "artifacts"),
            "--artifact-root",
            str(root),
        ),
    )

    assert result.exit_code == EXIT_INPUT_ERROR, result.output
    assert "clientA-private-workspace" not in result.output
    assert "artifacts" in result.output
