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

import click
import typer

from evidence_collector import __version__
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._logging import configure_logging, emit_event
from evidence_collector.cli._state import console, is_json_logs, set_json_logs
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


# Exit code for "the command could not run at all", deliberately distinct from
# the release-verdict codes. 0/1/2 mean ready/conditional/not_ready, so an
# unhandled exception exiting 1 — Click's default — was indistinguishable from a
# `conditional` verdict, and a pipeline following the documented gate semantics
# read a crash (with no bundle written) as "proceed with a warning". 3 is
# already the input/IO failure code used by verify, compare and evaluate.
EXIT_COMMAND_FAILED = 3

# Click exits 2 for every usage error: a rejected option value, an unknown
# flag, a missing argument, a path failing its `exists=` / `file_okay=` check.
# In this CLI 2 is a release verdict — `not_ready` — so a typo in `--fail-on`,
# or a directory passed where a bundle was expected, came back as "this release
# is not ready" and a pipeline gating on the documented codes acted on a verdict
# the tool never reached. The README states the contract plainly: every failure
# that is not a release verdict exits 3, and it names a rejected
# `--predicate-type` as an example.
#
# It has to be corrected here rather than around `app()`. Click's standalone
# mode catches `UsageError` itself, prints it, and calls `sys.exit(exit_code)`,
# so nothing distinguishable propagates — by the time the caller sees
# `SystemExit(2)` it is indistinguishable from a genuine `not_ready`. Rebinding
# the class attribute changes the code at its source, and covers every
# `UsageError` subclass (`BadParameter`, `MissingParameter`, `NoSuchOption`)
# since they all inherit it.
click.UsageError.exit_code = EXIT_INPUT_ERROR


def _report_command_failure(exc: BaseException) -> None:
    """Print one actionable line for an unhandled exception, no raw traceback.

    The full traceback is still available behind ``--verbose``; without it the
    user got a Rich-rendered stack ending in a bare ``FileNotFoundError`` with
    the developer's absolute paths, and under ``--json-logs`` stdout stayed
    completely empty, breaking the NDJSON contract on the error path.
    """
    detail = str(exc).strip() or exc.__class__.__name__
    if is_json_logs():
        emit_event("command_failed", error_type=exc.__class__.__name__, reason=detail)
    else:
        console.print(f"[red]{exc.__class__.__name__}:[/red] {detail}")
        console.print("[dim]Re-run with --verbose for the full traceback.[/dim]")
    if any(flag in sys.argv for flag in ("-v", "--verbose")):
        console.print_exception()


def main() -> None:
    """Console-script entrypoint."""
    _force_utf8_std_streams()
    # Print banner only when stdout is a TTY, to avoid polluting pipelines.
    if sys.stdout.isatty():
        console.print(
            f"[bold]Secure SDLC Evidence Collector[/bold] v{__version__} · "
            f"started at {datetime.now(tz=UTC).isoformat()}"
        )
    try:
        app()
    except Exception as exc:
        # SystemExit derives from BaseException, so every deliberate exit —
        # including typer.Exit — passes through untouched. Only genuinely
        # unhandled exceptions land here.
        _report_command_failure(exc)
        raise SystemExit(EXIT_COMMAND_FAILED) from exc


if __name__ == "__main__":
    main()
