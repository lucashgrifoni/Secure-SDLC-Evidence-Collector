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
