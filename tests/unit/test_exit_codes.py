"""Contract tests for the ``--fail-on`` exit-code matrix.

The exit code *is* the gate: it is the only thing a pipeline reads to decide
whether a release proceeds. Until this file existed nothing pinned the matrix,
and the README documented it backwards — it claimed ``conditional`` exits ``1``
without mentioning that the **default** ``--fail-on=not_ready`` makes it exit
``0``. Anyone wiring a gate from the README alone shipped conditional releases
silently.

These tests lock all nine cells so the documented table and the code cannot
drift apart again.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from evidence_collector.cli._exit_codes import (
    EXIT_INPUT_ERROR,
    exit_code_for_status,
    fail_on_exit_code,
)
from evidence_collector.domain.enums import ReleaseStatus

# (status, --fail-on, expected exit code) — mirrors the README "Exit codes" table.
_MATRIX = [
    (ReleaseStatus.READY, "ready", 0),
    (ReleaseStatus.READY, "conditional", 0),
    (ReleaseStatus.READY, "not_ready", 0),
    (ReleaseStatus.CONDITIONAL, "ready", 1),
    (ReleaseStatus.CONDITIONAL, "conditional", 1),
    # The cell that surprises people: the default threshold lets a
    # conditional release through with a success exit.
    (ReleaseStatus.CONDITIONAL, "not_ready", 0),
    (ReleaseStatus.NOT_READY, "ready", 2),
    (ReleaseStatus.NOT_READY, "conditional", 2),
    (ReleaseStatus.NOT_READY, "not_ready", 2),
]


@pytest.mark.parametrize(("status", "threshold", "expected"), _MATRIX)
def test_fail_on_matrix(status: ReleaseStatus, threshold: str, expected: int) -> None:
    assert fail_on_exit_code(status, threshold) == expected


def test_default_threshold_lets_conditional_pass() -> None:
    """Named separately because it is the one cell the README used to get wrong."""
    assert fail_on_exit_code(ReleaseStatus.CONDITIONAL, "not_ready") == 0


def test_threshold_is_case_insensitive() -> None:
    assert fail_on_exit_code(ReleaseStatus.CONDITIONAL, "CONDITIONAL") == 1


@pytest.mark.parametrize("threshold", ["banana", "", "not-ready", "notready"])
def test_unknown_threshold_falls_back_to_the_strictest_reading(threshold: str) -> None:
    """An unrecognised ``--fail-on`` must never be *weaker* than a valid one.

    The value is not validated by Typer, so a typo reaches this function. The
    fallback returns the natural exit code for the status, which is the maximum
    strictness available — a typo can produce a false red, never a false green.
    """
    for status in ReleaseStatus:
        assert fail_on_exit_code(status, threshold) == exit_code_for_status(status)
        # And it is never more permissive than any valid threshold would be.
        assert fail_on_exit_code(status, threshold) >= min(
            fail_on_exit_code(status, valid) for valid in ("ready", "conditional", "not_ready")
        )


def test_natural_exit_codes() -> None:
    assert exit_code_for_status(ReleaseStatus.READY) == 0
    assert exit_code_for_status(ReleaseStatus.CONDITIONAL) == 1
    assert exit_code_for_status(ReleaseStatus.NOT_READY) == 2


# ---------------------------------------------------------------------------
# --fail-on rejects unknown values (UX-03)
#
# The flag was never validated: an unrecognized value silently fell back to the
# natural exit code. The fallback is provably the strictest reading — a typo
# can only produce a false red, never a false green — but it is still a typo
# the user never hears about, on the flag that decides whether a pipeline
# stops. Sibling flags (--risk-mode, --profile, --policy) already reject.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["banana", "", "not-ready", "notready", "READY!"])
def test_validate_fail_on_rejects_unknown_values(value: str) -> None:
    import typer

    from evidence_collector.cli._exit_codes import validate_fail_on

    with pytest.raises(typer.BadParameter) as excinfo:
        validate_fail_on(value)
    # The message must name the accepted values, not just complain.
    for accepted in ("ready", "conditional", "not_ready"):
        assert accepted in str(excinfo.value)


@pytest.mark.parametrize("value", ["ready", "conditional", "not_ready", "NOT_READY"])
def test_validate_fail_on_accepts_and_normalizes(value: str) -> None:
    from evidence_collector.cli._exit_codes import validate_fail_on

    assert validate_fail_on(value) == value.lower()


def _run_cli(*argv: str) -> int:
    """Invoke the real console entrypoint and return the process exit code.

    `CliRunner` calls the Typer app directly and never reaches `main()`, which
    is where this project maps Click's exceptions onto its own codes — so a
    CliRunner assertion cannot see the contract a user experiences. It also
    made this suite depend on Typer's internals: the first version of the fix
    rebound `click.UsageError.exit_code`, which worked against typer 0.24 and
    silently stopped working against 0.27. Measuring the process exit code is
    the contract, and it holds whichever Typer resolves.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "evidence_collector.cli.main", *argv],
        capture_output=True,
        check=False,
        cwd=Path(__file__).resolve().parents[2],
    )
    return completed.returncode


@pytest.mark.parametrize(
    ("label", "argv"),
    [
        ("rejected --fail-on value", ["run", "--fail-on", "bogus"]),
        ("rejected --predicate-type", ["statement", "--predicate-type", "bogus", "b.json"]),
        ("unknown flag", ["run", "--no-such-flag"]),
        ("missing required argument", ["verify"]),
    ],
    ids=["fail-on", "predicate-type", "unknown-flag", "missing-argument"],
)
def test_usage_errors_exit_with_the_input_error_code(label: str, argv: list[str]) -> None:
    """Click exits 2 for a usage error; in this CLI 2 means `not_ready`.

    So a typo in `--fail-on`, or a directory passed where a bundle was
    expected, came back as a release verdict the tool never actually reached —
    and a pipeline gating on the documented codes acted on it. The README is
    explicit: every failure that is not a release verdict exits 3, and it names
    a rejected `--predicate-type` as an example.
    """
    assert _run_cli(*argv) == EXIT_INPUT_ERROR, label


def test_a_directory_where_a_bundle_is_expected_is_an_input_error(tmp_path: Path) -> None:
    """`verify <dir>` is a bad input, not a `not_ready` release."""
    for command in ("verify", "vex", "statement", "guac", "enrich"):
        assert _run_cli(command, str(tmp_path)) == EXIT_INPUT_ERROR, command


def test_a_real_not_ready_verdict_still_exits_two(tmp_path: Path) -> None:
    """The point of the change is to stop 2 being ambiguous, not to retire it."""
    assert (
        _run_cli(
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--output-dir",
            str(tmp_path / "out"),
        )
        == 2
    )


def test_help_and_version_still_exit_zero() -> None:
    """`standalone_mode=False` means Click no longer exits 0 on our behalf."""
    assert _run_cli("--version") == 0
    assert _run_cli("--help") == 0
