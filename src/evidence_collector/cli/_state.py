"""Cross-command CLI state.

The CLI keeps two pieces of process-wide state:

* a JSON-logs flag toggled by ``--json-logs`` / ``SDLC_JSON_LOGS`` so that
  every command can decide whether to emit Rich tables or NDJSON events,
* a shared :class:`rich.console.Console` instance so all commands write
  through the same stdout/stderr handling.

These primitives live in their own module so command modules can import
them without pulling in Typer or the rest of ``main.py``.
"""

from __future__ import annotations

import os
from typing import Final

from pydantic import TypeAdapter
from rich.console import Console

from evidence_collector.domain.models import NormalizedEvidence

console: Final[Console] = Console()

EVIDENCE_ADAPTER: Final[TypeAdapter[list[NormalizedEvidence]]] = TypeAdapter(
    list[NormalizedEvidence]
)

_JSON_LOGS_ENABLED: bool = False
_TRUE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes"})


def set_json_logs(enabled: bool) -> None:
    """Toggle the process-wide NDJSON-logs flag.

    Honors the ``SDLC_JSON_LOGS`` environment variable as a fallback so
    pipelines can opt in without touching command lines.
    """
    global _JSON_LOGS_ENABLED
    env_value = os.environ.get("SDLC_JSON_LOGS", "").lower()
    _JSON_LOGS_ENABLED = bool(enabled) or env_value in _TRUE_VALUES


def is_json_logs() -> bool:
    """Return whether the CLI should emit NDJSON events instead of Rich tables."""
    return _JSON_LOGS_ENABLED
