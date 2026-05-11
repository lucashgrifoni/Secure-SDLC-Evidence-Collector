"""``sdlc-evidence exceptions`` — inspect and validate waiver files."""

from __future__ import annotations

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
        path: Annotated[Path, typer.Argument(help="Exception YAML/JSON to validate")],
    ) -> None:
        """Validate an exception file against the canonical schema."""
        try:
            exception = parse_exception(path)
        except (ParseError, FileNotFoundError) as exc:
            console.print(f"[red]Invalid exception file:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(
            f"[green]{exception.exception_id}[/green] valid · "
            f"control={exception.control_id} · approver={exception.approver} "
            f"· expires_at={exception.expires_at.isoformat()}"
        )

    @exceptions_app.command("list")
    def cmd_exceptions_list(
        directory: Annotated[
            Path, typer.Argument(help="Directory containing exception YAML/JSON files")
        ],
    ) -> None:
        """Walk a directory and list every valid exception."""
        if not directory.is_dir():
            console.print(f"[red]Not a directory:[/red] {directory}")
            raise typer.Exit(code=2)
        table = Table(title=f"Exceptions in {directory}")
        table.add_column("Exception ID")
        table.add_column("Control")
        table.add_column("Approver")
        table.add_column("Expires at")
        table.add_column("Scope")
        valid = 0
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
            valid += 1
            scope_bits: list[str] = []
            if exc.scope.application:
                scope_bits.append(f"app={exc.scope.application}")
            if exc.scope.release_id:
                scope_bits.append(f"release={exc.scope.release_id}")
            table.add_row(
                exc.exception_id,
                exc.control_id,
                exc.approver,
                exc.expires_at.isoformat(),
                ", ".join(scope_bits) or "global",
            )
        console.print(table)
        console.print(f"[bold]{valid}[/bold] valid · [yellow]{invalid}[/yellow] invalid")
