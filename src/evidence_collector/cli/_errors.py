"""Compact errors shared by command handlers and the entrypoint."""

from __future__ import annotations

from pydantic import ValidationError
from rich.console import Console

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import is_json_logs

error_console = Console(stderr=True)


def error_detail(exc: BaseException) -> str:
    """Describe validation errors without input dumps or documentation URLs."""
    if isinstance(exc.__cause__, ValidationError):
        exc = exc.__cause__
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{exc.title}.{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
            for error in exc.errors(include_url=False, include_input=False)
        )
    return " ".join(str(exc).splitlines()).strip() or exc.__class__.__name__


def report_error(
    message: str,
    exc: BaseException | None = None,
    *,
    event: str = "command_failed",
    **fields: object,
) -> None:
    """Emit one NDJSON event on stdout or one plain error line on stderr."""
    detail = f"{message}: {error_detail(exc)}" if exc is not None else message
    detail = " ".join(detail.splitlines())
    if is_json_logs():
        emit_event(event, reason=detail, **fields)
    else:
        error_console.print(detail, markup=False, highlight=False, soft_wrap=True)
