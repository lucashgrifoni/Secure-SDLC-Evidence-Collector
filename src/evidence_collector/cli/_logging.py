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


class _JsonLineFormatter(logging.Formatter):
    """One JSON object per log record, so stderr stays NDJSON too."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "event": "log",
                "level": record.levelname.lower(),
                "logger": record.name,
                "message": record.getMessage(),
            },
            ensure_ascii=False,
            sort_keys=True,
        )


def configure_logging(verbose: bool) -> None:
    """Configure ``logging`` to DEBUG when verbose, otherwise INFO.

    Under JSON logs the records are JSON lines on stderr: plain-text lines
    there broke the stream for anyone merging stderr into stdout.
    """
    level = logging.DEBUG if verbose else logging.INFO
    if is_json_logs():
        handler = logging.StreamHandler()
        handler.setFormatter(_JsonLineFormatter())
        logging.basicConfig(level=level, handlers=[handler])
        return
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
