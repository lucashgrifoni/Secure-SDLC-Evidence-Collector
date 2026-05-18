"""``sdlc-evidence schema`` — dump the bundle JSON Schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli._state import console
from evidence_collector.domain.models import EvidenceBundle


def register(app: typer.Typer) -> None:
    """Attach the ``schema`` command to ``app``."""

    @app.command("schema")
    def cmd_schema(
        output_path: Annotated[
            Path | None,
            typer.Option("--output", help="Write JSON Schema to this file instead of stdout"),
        ] = None,
    ) -> None:
        """Emit the JSON Schema for EvidenceBundle so teams can validate externally."""
        schema = EvidenceBundle.model_json_schema()
        payload = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False)
        if output_path is None:
            typer.echo(payload)
            return
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
        console.print(f"[green]EvidenceBundle JSON Schema[/green] → {output_path}")
