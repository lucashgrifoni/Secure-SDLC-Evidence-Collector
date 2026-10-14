"""``sdlc-evidence doctor`` — pre-flight environment health check."""

from __future__ import annotations

import json
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._preflight import doctor_checks, doctor_payload
from evidence_collector.cli._state import console, is_json_logs

# The checks live in `_preflight`, which imports the standard library only, so
# they still run when a dependency this module needs is missing.
__all__ = ["doctor_checks", "register"]


def register(app: typer.Typer) -> None:
    """Attach the ``doctor`` command to ``app``."""

    @app.command("doctor")
    def cmd_doctor(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit results as JSON instead of a Rich table"),
        ] = False,
    ) -> None:
        """Check the local environment is ready to run the collector.

        Exits 0 when every required check passes (optional ones never fail);
        exits 1 when any required check fails. Designed to be wired into CI
        or as a pre-flight step in operator runbooks.
        """
        results = doctor_checks()
        failed = [(label, detail) for label, ok, detail in results if not ok]

        if is_json_logs():
            emit_event("doctor_checked", **doctor_payload(results))
        elif json_output:
            typer.echo(json.dumps(doctor_payload(results), indent=2))
        else:
            table = Table(title="sdlc-evidence doctor", show_header=True)
            table.add_column("Check")
            table.add_column("Status")
            table.add_column("Detail", overflow="fold")
            for label, ok, detail in results:
                status = "[green]ok[/green]" if ok else "[red]fail[/red]"
                table.add_row(label, status, detail)
            console.print(table)
            if failed:
                console.print(f"[red]{len(failed)} required check(s) failed.[/red]")
            else:
                console.print("[green]All required checks passed.[/green]")

        if failed:
            raise typer.Exit(code=1)
