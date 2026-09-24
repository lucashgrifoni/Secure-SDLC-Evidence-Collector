"""Exit-code rules for the CLI.

* ``ready``       → exit 0
* ``conditional`` → exit 1
* ``not_ready``   → exit 2

The ``--fail-on`` flag lets callers downgrade non-zero exits when they
want to ignore a softer verdict (for example, treat ``conditional`` as a
success on a non-blocking pipeline).
"""

from __future__ import annotations

from typing import Final

import typer

from evidence_collector.domain.enums import ReleaseStatus

_STATUS_RANK: Final[dict[ReleaseStatus, int]] = {
    ReleaseStatus.READY: 0,
    ReleaseStatus.CONDITIONAL: 1,
    ReleaseStatus.NOT_READY: 2,
}

_THRESHOLD_RANK: Final[dict[str, int]] = {
    "ready": 0,
    "conditional": 1,
    "not_ready": 2,
}


# Reserved for "the command could not run": a missing, unreadable or malformed
# input, or an unhandled failure. Deliberately outside the verdict range, which
# owns 0 (ready), 1 (conditional) and 2 (not_ready).
#
# Five commands used to return 2 for exactly this — the same code as a
# not_ready release — so a CI wrapper had to keep a per-subcommand table, and
# `2` meant three different things at once (not_ready, bad input, and Click's
# own usage error). Two tests in this repo pinned the two contradictory
# contracts against each other.
EXIT_INPUT_ERROR: Final[int] = 3

# What "a malformed input file" is allowed to raise, for the commands that read
# a bundle.json before doing anything with it.
#
# Eight of them named `OSError` and `json.JSONDecodeError` and stopped there,
# which covers a missing file and a syntax error but not the rest of what a
# corrupted file does on the way in. Each of the others reached the top-level
# handler instead, so the exit code stayed correct at 3 while the message
# became a bare `ValueError: Exceeds the limit (4300 digits)... use
# sys.set_int_max_str_digits()` — naming neither the file nor anything the
# operator can act on, and pointing at a remedy that is not the problem. A
# pipeline running one of these over many bundles could not tell which one
# failed.
#
# `ValueError` is what makes it work: `json.JSONDecodeError`, the 4300-digit
# int conversion cap and `UnicodeDecodeError` from a mis-encoded byte are all
# subclasses. `RecursionError` (deeply nested JSON) is not, so it is named.
#
# Watch the clause order where a handler also catches Pydantic's
# `ValidationError` on the *same* `try`: that is a `ValueError` subclass too,
# so it must come first or this tuple swallows it and reports a schema
# mismatch as an unreadable file.
UNREADABLE_INPUT: Final[tuple[type[Exception], ...]] = (OSError, RecursionError, ValueError)

FAIL_ON_VALUES: Final[tuple[str, ...]] = ("ready", "conditional", "not_ready")


def validate_fail_on(value: str) -> str:
    """Return ``value`` normalized, or raise ``typer.BadParameter``.

    ``--fail-on`` was never validated: an unrecognized value silently fell back
    to the natural exit code for the status. The fallback is provably the
    strictest reading — a typo can only produce a false red, never a false
    green — but it is still a typo the user never hears about, on the flag that
    decides whether a pipeline stops. Sibling flags (``--risk-mode``,
    ``--profile``, ``--policy``) all reject unknown values already.
    """
    normalized = value.lower()
    if normalized not in FAIL_ON_VALUES:
        raise typer.BadParameter(f"--fail-on must be one of {list(FAIL_ON_VALUES)}; got '{value}'.")
    return normalized


def exit_code_for_status(status: ReleaseStatus) -> int:
    """Translate a :class:`ReleaseStatus` into the default exit code."""
    return _STATUS_RANK[status]


def fail_on_exit_code(status: ReleaseStatus, threshold: str) -> int:
    """Apply the ``--fail-on`` threshold to a release status.

    Returns the natural exit code for ``status`` only when ``status``
    reaches or exceeds the configured ``threshold``; otherwise returns 0.
    Unknown thresholds fall back to the natural exit code.
    """
    threshold_value = threshold.lower()
    if threshold_value not in _THRESHOLD_RANK:
        return exit_code_for_status(status)
    status_rank = _STATUS_RANK[status]
    if status_rank >= _THRESHOLD_RANK[threshold_value]:
        return status_rank if status_rank > 0 else 0
    return 0
