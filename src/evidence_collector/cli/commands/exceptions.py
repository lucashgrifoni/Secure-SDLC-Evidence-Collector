"""``sdlc-evidence exceptions`` — inspect and validate waiver files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._state import console
from evidence_collector.domain.models import EvidenceException
from evidence_collector.parsers import parse_exception
from evidence_collector.parsers._common import ParseError


def _in_force(exception: EvidenceException, now: datetime) -> bool:
    """Whether the engine would honour this waiver right now.

    These commands used to test only `now >= expires_at`, so a waiver approved
    for a future window was reported as "valid" and counted "active" while
    `run` and `evaluate` refused it as not yet in effect. The window has two
    ends — `examples/sample_release/exceptions/README.md` documents it as
    half-open — and a reporting command that disagrees with the gate about
    which waivers are live is worse than one that says nothing.

    Scope is deliberately not considered: these commands inspect files without
    an application or release in hand, so a scoped waiver is neither in nor out
    of scope here. Only the time window is decidable.
    """
    return exception.approved_at <= now < exception.expires_at


def _window_note(exception: EvidenceException, now: datetime) -> str:
    """Say why a well-formed waiver is not in force, if it is not."""
    if now >= exception.expires_at:
        return " [yellow](EXPIRED — waives nothing)[/yellow]"
    if now < exception.approved_at:
        return (
            f" [yellow](NOT YET IN EFFECT until "
            f"{exception.approved_at.isoformat()} — waives nothing)[/yellow]"
        )
    return ""


def register(app: typer.Typer) -> None:
    """Attach the ``exceptions`` sub-app to ``app``."""

    exceptions_app = typer.Typer(
        name="exceptions",
        help="Inspect and validate Secure SDLC exception (waiver) files.",
        no_args_is_help=True,
        add_completion=False,
    )
    app.add_typer(exceptions_app)

    @exceptions_app.command("validate")
    def cmd_exceptions_validate(
        paths: Annotated[
            list[Path],
            typer.Argument(help="One or more exception YAML/JSON files to validate"),
        ],
    ) -> None:
        """Validate one or more exception files against the canonical schema.

        Accepts multiple paths so it can be wired as a ``pre-commit`` hook:
        pre-commit passes every matched, staged file in a single
        invocation. Each file is reported individually; the command exits
        ``EXIT_INPUT_ERROR`` if *any* file is missing or invalid, 0 when all
        are valid.

        It used to exit 1 here, which the README reserves for the
        ``conditional`` verdict and nothing else — and a waiver file that
        does not exist is a bad input, not a softer release outcome. It also
        disagreed with its sibling ``exceptions list``. Any exit code works
        for a pre-commit hook, which only distinguishes zero from non-zero,
        so the taxonomy wins.
        """
        if not paths:
            console.print("[red]No exception files given.[/red]")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        invalid = 0
        for path in paths:
            try:
                exception = parse_exception(path)
            except (ParseError, FileNotFoundError) as exc:
                invalid += 1
                console.print(f"[red]Invalid exception file[/red] {path}: {exc}")
                continue
            # Expiry is not a schema error, so it must not change this
            # command's exit contract (it ships as a pre-commit hook). It is
            # still worth saying out loud: a well-formed waiver that expired
            # waives nothing, and silence here reads as approval.
            expiry_note = _window_note(exception, datetime.now(tz=UTC))
            console.print(
                f"[green]{exception.exception_id}[/green] valid · "
                f"control={exception.control_id} · approver={exception.approver} "
                f"· expires_at={exception.expires_at.isoformat()}{expiry_note}"
            )
        if invalid:
            raise typer.Exit(code=EXIT_INPUT_ERROR)

    @exceptions_app.command("list")
    def cmd_exceptions_list(
        directory: Annotated[
            Path, typer.Argument(help="Directory containing exception YAML/JSON files")
        ],
    ) -> None:
        """Walk a directory and list every exception, flagging expired ones."""
        if not directory.is_dir():
            console.print(f"[red]Not a directory:[/red] {directory}")
            raise typer.Exit(code=EXIT_INPUT_ERROR)
        table = Table(title=f"Exceptions in {directory}")
        table.add_column("Exception ID")
        table.add_column("Control")
        table.add_column("Approver")
        table.add_column("Expires at")
        table.add_column("Scope")
        now = datetime.now(tz=UTC)
        parseable = 0
        dormant = 0
        invalid = 0
        for path in sorted(directory.rglob("*")):
            if path.suffix.lower() not in {".yaml", ".yml", ".json"} or not path.is_file():
                continue
            try:
                exc = parse_exception(path)
            except (ParseError, FileNotFoundError) as err:
                invalid += 1
                console.print(f"[yellow]skipped[/yellow] {path}: {err}")
                continue
            parseable += 1
            in_force = _in_force(exc, now)
            if not in_force:
                dormant += 1
            scope_bits: list[str] = []
            if exc.scope.application:
                scope_bits.append(f"app={exc.scope.application}")
            if exc.scope.release_id:
                scope_bits.append(f"release={exc.scope.release_id}")
            # Expiry is rendered on the date itself rather than in a sixth
            # column: an extra column squeezes the exception ID to unreadable
            # width on an 80-column terminal, and the state belongs to the date.
            expires_cell = exc.expires_at.isoformat()
            if now >= exc.expires_at:
                expires_cell = f"[yellow]{expires_cell} (expired)[/yellow]"
            elif now < exc.approved_at:
                expires_cell = (
                    f"[yellow]{expires_cell} (not yet in effect until "
                    f"{exc.approved_at.isoformat()})[/yellow]"
                )
            table.add_row(
                exc.exception_id,
                exc.control_id,
                exc.approver,
                expires_cell,
                ", ".join(scope_bits) or "global",
            )
        console.print(table)
        # "valid" used to mean "parsed", so an expired waiver was reported as
        # `1 valid · 0 invalid` — the opposite of what a reader needs, and this
        # command ships as a pre-commit hook. A waiver that is not in force is
        # now counted separately: the file is still well-formed, it just does
        # not waive anything. "not in force" rather than "expired" because a
        # waiver dated in the future is equally dormant, and calling that
        # "active" is what made this command disagree with the release gate.
        console.print(
            f"[bold]{parseable - dormant}[/bold] active · "
            f"[yellow]{dormant}[/yellow] not in force · "
            f"[yellow]{invalid}[/yellow] unparseable"
        )
