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

import pytest

from evidence_collector.cli._exit_codes import exit_code_for_status, fail_on_exit_code
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
