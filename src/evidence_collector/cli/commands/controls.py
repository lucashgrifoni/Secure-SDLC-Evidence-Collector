"""``sdlc-evidence controls`` — print the active control catalog."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs


def register(app: typer.Typer) -> None:
    """Attach the ``controls`` command to ``app``."""

    @app.command("controls")
    def cmd_controls(
        catalog_path: Annotated[
            Path | None,
            typer.Option(
                "--catalog", help="Control catalog: a path, or the bare name of a bundled catalog"
            ),
        ] = None,
    ) -> None:
        """Print the control catalog currently used for evaluation."""
        from evidence_collector.controls import default_catalog, load_catalog

        controls = load_catalog(catalog_path) if catalog_path else list(default_catalog())
        if is_json_logs():
            emit_event(
                "controls_listed",
                controls=[control.model_dump(mode="json") for control in controls],
            )
            return
        table = Table(title="Secure SDLC Control Catalog", show_lines=False)
        table.add_column("Control ID")
        table.add_column("Framework")
        table.add_column("Criticality")
        table.add_column("Required evidence")
        table.add_column("Recommended evidence")
        for control in controls:
            table.add_row(
                control.control_id,
                control.framework.value,
                control.criticality.value,
                ", ".join(t.value for t in control.required_evidence_types) or "-",
                ", ".join(t.value for t in control.recommended_evidence_types) or "-",
            )
        console.print(table)
