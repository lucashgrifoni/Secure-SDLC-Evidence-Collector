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

from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli.main import app


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
