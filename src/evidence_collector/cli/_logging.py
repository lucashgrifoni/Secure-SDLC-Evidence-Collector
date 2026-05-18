"""Logging primitives shared across CLI commands.

* :func:`configure_logging` wires up ``logging.basicConfig`` based on the
  ``--verbose`` flag.
* :func:`emit_event` is the single emission point for NDJSON events. In
  Rich (human) mode it is a no-op so command modules can call it
  unconditionally; the visible UI is produced by ``_render.py`` helpers.

Keeping a single emission point means a future migration to
``structlog`` can replace the body without touching command modules.
"""

from __future__ import annotations

import json
import logging

import typer

from evidence_collector.cli._state import is_json_logs


def configure_logging(verbose: bool) -> None:
    """Configure ``logging`` to DEBUG when verbose, otherwise INFO."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )


def emit_event(event: str, **fields: object) -> None:
    """Emit a structured NDJSON event line when JSON-logs mode is on."""
    if not is_json_logs():
        return
    payload: dict[str, object] = {"event": event, **fields}
    typer.echo(json.dumps(payload, ensure_ascii=False, sort_keys=True))
