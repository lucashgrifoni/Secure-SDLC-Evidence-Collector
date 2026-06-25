"""``sdlc-evidence schema`` — dump the bundle JSON Schema."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli._state import console
from evidence_collector.schema import bundle_json_schema_text


def register(app: typer.Typer) -> None:
    """Attach the ``schema`` command to ``app``."""

    @app.command("schema")
    def cmd_schema(
        output_path: Annotated[
            Path | None,
            typer.Option("--output", help="Write JSON Schema to this file instead of stdout"),
        ] = None,
    ) -> None:
        """Emit the self-describing JSON Schema for EvidenceBundle ($schema + $id)."""
        text = bundle_json_schema_text()
        if output_path is None:
            # ``text`` already ends with a newline; do not add another.
            typer.echo(text, nl=False)
            return
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Force LF so the artifact is byte-identical regardless of the OS that
        # generated it (the committed contract + its freshness gate depend on
        # this; Windows would otherwise translate \n to \r\n).
        output_path.write_text(text, encoding="utf-8", newline="\n")
        console.print(f"[green]EvidenceBundle JSON Schema[/green] → {output_path}")
