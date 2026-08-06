"""``sdlc-evidence guac`` — emit a GUAC-collector container for a bundle (T6.9).

Reads an existing bundle.json and writes a JSON container that
``guacone collect files`` can ingest. The container is a thin
projection of the bundle (one entry per evidence) so GUAC stitches
the release into its supply-chain graph without bespoke parsers.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters.guac import build_guac_collection


def register(app: typer.Typer) -> None:
    """Attach the ``guac`` command to ``app``."""

    @app.command("guac")
    def cmd_guac(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                exists=True,
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json to translate into GUAC ingest format.",
            ),
        ],
        output: Annotated[
            Path,
            typer.Option(
                "--output",
                "-o",
                help="Where to write the GUAC collection JSON.",
            ),
        ] = Path("guac.json"),
    ) -> None:
        """Translate BUNDLE_PATH into a GUAC-collector container."""
        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if is_json_logs():
                emit_event("guac_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
        try:
            bundle = EvidenceBundle.model_validate(raw)
        except ValidationError as exc:
            if is_json_logs():
                emit_event("guac_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        document = build_guac_collection(bundle)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(document, indent=2, sort_keys=False), encoding="utf-8")

        if is_json_logs():
            emit_event(
                "guac_emitted",
                bundle=str(bundle_path),
                output=str(output),
                documents=len(document.get("documents", [])),
            )
        else:
            console.print(
                f"[green]GUAC collection[/green] · {len(document.get('documents', []))} "
                f"document(s) → {output}"
            )
