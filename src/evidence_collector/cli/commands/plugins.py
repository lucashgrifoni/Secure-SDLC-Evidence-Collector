"""``sdlc-evidence plugins`` — list discovered parser/collector plugins."""

from __future__ import annotations

import json

import typer
from rich.table import Table

from evidence_collector.cli._state import console, is_json_logs


def register(app: typer.Typer) -> None:
    """Attach the ``plugins`` command to ``app``."""

    @app.command("plugins")
    def cmd_plugins() -> None:
        """List parser and collector plugins registered via entry-points."""
        from evidence_collector.plugins import list_plugins

        listing = list_plugins()
        if is_json_logs():
            typer.echo(json.dumps(listing, indent=2, sort_keys=True))
            return
        table = Table(title="Discovered plugins", show_header=True)
        table.add_column("Group")
        table.add_column("Names", overflow="fold")
        for group, names in listing.items():
            table.add_row(group, ", ".join(names) if names else "[dim]<none>[/dim]")
        console.print(table)
        console.print(
            "[dim]See docs/plugins.md for how to register custom parsers and collectors.[/dim]"
        )
