"""``sdlc-evidence exceptions`` — inspect and validate waiver files."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.cli._state import console
from evidence_collector.parsers import parse_exception
from evidence_collector.parsers._common import ParseError


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
        1 if *any* file is invalid, 0 when all are valid.
        """
        if not paths:
            console.print("[red]No exception files given.[/red]")
            raise typer.Exit(code=2)
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
            expiry_note = (
                " [yellow](EXPIRED — waives nothing)[/yellow]"
                if datetime.now(tz=UTC) >= exception.expires_at
                else ""
            )
            console.print(
                f"[green]{exception.exception_id}[/green] valid · "
                f"control={exception.control_id} · approver={exception.approver} "
                f"· expires_at={exception.expires_at.isoformat()}{expiry_note}"
            )
        if invalid:
            raise typer.Exit(code=1)

    @exceptions_app.command("list")
    def cmd_exceptions_list(
        directory: Annotated[
            Path, typer.Argument(help="Directory containing exception YAML/JSON files")
        ],
    ) -> None:
        """Walk a directory and list every exception, flagging expired ones."""
        if not directory.is_dir():
            console.print(f"[red]Not a directory:[/red] {directory}")
            raise typer.Exit(code=2)
        table = Table(title=f"Exceptions in {directory}")
        table.add_column("Exception ID")
        table.add_column("Control")
        table.add_column("Approver")
        table.add_column("Expires at")
        table.add_column("Scope")
        now = datetime.now(tz=UTC)
        parseable = 0
        expired = 0
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
            is_expired = now >= exc.expires_at
            if is_expired:
                expired += 1
            scope_bits: list[str] = []
            if exc.scope.application:
                scope_bits.append(f"app={exc.scope.application}")
            if exc.scope.release_id:
                scope_bits.append(f"release={exc.scope.release_id}")
            # Expiry is rendered on the date itself rather than in a sixth
            # column: an extra column squeezes the exception ID to unreadable
            # width on an 80-column terminal, and the state belongs to the date.
            expires_cell = exc.expires_at.isoformat()
            if is_expired:
                expires_cell = f"[yellow]{expires_cell} (expired)[/yellow]"
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
        # command ships as a pre-commit hook. Expiry is now counted separately:
        # the file is still well-formed, it just no longer waives anything.
        console.print(
            f"[bold]{parseable - expired}[/bold] active · "
            f"[yellow]{expired}[/yellow] expired · "
            f"[yellow]{invalid}[/yellow] unparseable"
        )
