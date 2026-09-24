"""``sdlc-evidence sarif`` — write the bundle's unmet controls as SARIF 2.1.0.

Reads an existing bundle and writes one SARIF log with a result per
``missing`` or ``partial`` control, for a code scanning dashboard. The
command only writes the file; uploading it stays with the caller.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import typer
from pydantic import ValidationError

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR, UNREADABLE_INPUT
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_atomic
from evidence_collector.exporters.sarif_gaps import build_gap_sarif


def register(app: typer.Typer) -> None:
    """Attach the ``sarif`` command to ``app``."""

    @app.command("sarif")
    def cmd_sarif(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                # No exists=True, for the same reason as `vex`: Click would exit 2
                # (the not_ready code) before the body can exit EXIT_INPUT_ERROR.
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json whose unmet controls become SARIF results.",
            ),
        ],
        output: Annotated[
            Path,
            typer.Option(
                "--output",
                "-o",
                help="Where to write the SARIF 2.1.0 log.",
            ),
        ] = Path("gaps.sarif"),
    ) -> None:
        """Write one SARIF result per missing or partial control in BUNDLE_PATH."""
        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        except UNREADABLE_INPUT as exc:
            if is_json_logs():
                emit_event("sarif_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
        try:
            bundle = EvidenceBundle.model_validate(raw)
        except ValidationError as exc:
            if is_json_logs():
                emit_event("sarif_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        document = build_gap_sarif(bundle, artifact_uri=_artifact_uri(bundle_path))
        write_atomic(output, json.dumps(document, indent=2))

        results = len(document["runs"][0]["results"])
        if is_json_logs():
            emit_event(
                "sarif_emitted", bundle=str(bundle_path), output=str(output), results=results
            )
        else:
            console.print(f"[green]SARIF[/green] · {results} unmet control(s) → {output}")


def _artifact_uri(bundle_path: Path) -> str:
    """The bundle's path relative to the working directory, as a SARIF URI.

    Code scanning resolves a location against the repository root, which is
    the working directory in a pipeline. A bundle outside it has no such
    path, so its file name is the best the location can say. SARIF wants an
    RFC 3986 reference, so spaces and reserved characters are percent-encoded.
    """
    try:
        path = bundle_path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        path = bundle_path.name
    return quote(path, safe="/")
