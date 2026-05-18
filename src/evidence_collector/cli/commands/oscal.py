"""``sdlc-evidence oscal`` — render the catalog as an OSCAL 1.1.x JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli._state import console


def register(app: typer.Typer) -> None:
    """Attach the ``oscal`` command to ``app``."""

    @app.command("oscal")
    def cmd_oscal(
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output", help="Write OSCAL Catalog JSON to this file instead of stdout"
            ),
        ] = None,
        catalog_path: Annotated[
            Path | None,
            typer.Option("--catalog", help="Override the default control catalog YAML"),
        ] = None,
    ) -> None:
        """Render the control catalog as an OSCAL Catalog JSON document.

        Useful for importing into OSCAL-native auditor tooling (FedRAMP,
        HITRUST, StateRAMP, etc.). The output conforms to OSCAL 1.1.x.
        """
        from evidence_collector.controls import default_catalog, load_catalog
        from evidence_collector.exporters.oscal import export_oscal_catalog

        controls = load_catalog(catalog_path) if catalog_path else list(default_catalog())
        payload = json.dumps(
            export_oscal_catalog(controls), indent=2, sort_keys=True, ensure_ascii=False
        )
        if output_path is None:
            typer.echo(payload)
            return
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload + "\n", encoding="utf-8")
        console.print(f"[green]OSCAL Catalog[/green] → {output_path}")
