"""``sdlc-evidence vex`` — emit an OpenVEX document from a bundle.json.

Reads an existing bundle and writes a single OpenVEX 0.2.0 JSON
document that restates the bundle's exploitability story per CVE.
Designed to live next to the bundle in a release artifact set so
downstream consumers (e.g. EU CRA evidence packs) can ingest VEX
without reverse-engineering the bundle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters.vex import build_openvex


def register(app: typer.Typer) -> None:
    """Attach the ``vex`` command to ``app``."""

    @app.command("vex")
    def cmd_vex(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                exists=True,
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json to translate into OpenVEX.",
            ),
        ],
        output: Annotated[
            Path,
            typer.Option(
                "--output",
                "-o",
                help="Where to write the OpenVEX JSON document.",
            ),
        ] = Path("openvex.json"),
    ) -> None:
        """Emit an OpenVEX 0.2.0 document derived from BUNDLE_PATH."""
        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if is_json_logs():
                emit_event("vex_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        try:
            bundle = EvidenceBundle.model_validate(raw)
        except ValidationError as exc:
            if is_json_logs():
                emit_event("vex_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        document = build_openvex(bundle)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=2, sort_keys=False), encoding="utf-8")

        statements = document.get("statements", [])
        if is_json_logs():
            emit_event(
                "vex_emitted",
                bundle=str(bundle_path),
                output=str(output),
                statements=len(statements),
            )
        else:
            console.print(f"[green]OpenVEX[/green] · {len(statements)} statement(s) → {output}")
