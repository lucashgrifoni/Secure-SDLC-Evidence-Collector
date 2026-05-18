"""Typer CLI for the Secure SDLC Evidence Collector.

This module is the console-script entrypoint registered as
``sdlc-evidence``. It builds the root :class:`typer.Typer` app, declares
the global ``--verbose`` / ``--json-logs`` / ``--version`` callback, and
delegates every command to a dedicated module under
:mod:`evidence_collector.cli.commands`. See
``docs/adr/0006-cli-command-modularization.md`` for the rationale.

External callers (tests, downstream tooling) keep importing :data:`app`
and :func:`_doctor_checks` from ``evidence_collector.cli.main``; both
are re-exported here so the previous import surface is preserved.
"""

from __future__ import annotations

import contextlib
import sys
from datetime import UTC, datetime
from typing import Annotated

import typer

from evidence_collector import __version__
from evidence_collector.cli._logging import configure_logging
from evidence_collector.cli._state import console, set_json_logs
from evidence_collector.cli.commands import register_all
from evidence_collector.cli.commands.doctor import doctor_checks as _doctor_checks

__all__ = ["_doctor_checks", "app", "main"]

app = typer.Typer(
    name="sdlc-evidence",
    help="Secure SDLC Evidence Collector — collect, evaluate and bundle release evidence.",
    no_args_is_help=False,
    add_completion=False,
)

register_all(app)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    json_logs: Annotated[
        bool,
        typer.Option(
            "--json-logs",
            help=(
                "Emit machine-readable NDJSON events instead of Rich tables. "
                "Useful in CI; can also be set with SDLC_JSON_LOGS=1."
            ),
        ),
    ] = False,
    version: Annotated[bool, typer.Option("--version", help="Print version and exit")] = False,
) -> None:
    """Secure SDLC Evidence Collector CLI."""
    set_json_logs(json_logs)
    if version:
        typer.echo(__version__)
        raise typer.Exit(code=0)
    configure_logging(verbose)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


def _force_utf8_std_streams() -> None:
    # Windows terminals default to cp1252 and crash on Rich's Unicode
    # separators (→, ⬆). Reconfigure both streams to UTF-8 so the CLI
    # works out-of-the-box without requiring PYTHONIOENCODING=utf-8.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    """Console-script entrypoint."""
    _force_utf8_std_streams()
    # Print banner only when stdout is a TTY, to avoid polluting pipelines.
    if sys.stdout.isatty():
        console.print(
            f"[bold]Secure SDLC Evidence Collector[/bold] v{__version__} · "
            f"started at {datetime.now(tz=UTC).isoformat()}"
        )
    app()


if __name__ == "__main__":
    main()
