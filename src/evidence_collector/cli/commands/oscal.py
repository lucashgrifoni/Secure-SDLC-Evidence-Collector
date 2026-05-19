"""``sdlc-evidence oscal`` — render OSCAL Catalog or Assessment Results JSON."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._state import console


class OscalKind(StrEnum):
    """Which OSCAL model to emit."""

    catalog = "catalog"
    assessment_results = "assessment-results"


def register(app: typer.Typer) -> None:
    """Attach the ``oscal`` command to ``app``."""

    @app.command("oscal")
    def cmd_oscal(
        output_path: Annotated[
            Path | None,
            typer.Option(
                "--output",
                help="Write OSCAL JSON to this file instead of stdout.",
            ),
        ] = None,
        catalog_path: Annotated[
            Path | None,
            typer.Option(
                "--catalog",
                help="Override the default control catalog YAML (catalog kind only).",
            ),
        ] = None,
        kind: Annotated[
            OscalKind,
            typer.Option(
                "--kind",
                "-k",
                case_sensitive=False,
                help=(
                    "Which OSCAL model to emit. ``catalog`` (default) renders "
                    "the control catalog. ``assessment-results`` renders the "
                    "per-release evaluations from a bundle.json and requires "
                    "``--bundle``."
                ),
            ),
        ] = OscalKind.catalog,
        bundle_path: Annotated[
            Path | None,
            typer.Option(
                "--bundle",
                help=(
                    "Path to bundle.json for the ``assessment-results`` kind. "
                    "Ignored when ``--kind catalog``."
                ),
                exists=False,
            ),
        ] = None,
    ) -> None:
        """Render the control catalog or assessment results as OSCAL 1.1.x JSON.

        Two modes:

        * ``--kind catalog`` (default) — emits the catalog defined under
          ``src/evidence_collector/controls/data/catalog.yaml`` (or the
          file passed via ``--catalog``).
        * ``--kind assessment-results --bundle bundle.json`` — emits the
          OSCAL Assessment Results document that maps the bundle's
          control evaluations to OSCAL findings + observations.
        """
        if kind is OscalKind.catalog:
            from evidence_collector.controls import default_catalog, load_catalog
            from evidence_collector.exporters.oscal import export_oscal_catalog

            controls = load_catalog(catalog_path) if catalog_path else list(default_catalog())
            payload = json.dumps(
                export_oscal_catalog(controls),
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
            _write_or_echo(payload, output_path, label="OSCAL Catalog")
            return

        if bundle_path is None or not bundle_path.is_file():
            console.print(
                "[red]--bundle is required and must exist for --kind assessment-results[/red]"
            )
            raise typer.Exit(code=2)

        from evidence_collector.domain.models import EvidenceBundle
        from evidence_collector.exporters.oscal import export_oscal_assessment_results

        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
            bundle = EvidenceBundle.model_validate(raw)
        except (OSError, json.JSONDecodeError) as exc:
            console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        except ValidationError as exc:
            console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        payload = json.dumps(
            export_oscal_assessment_results(bundle),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        _write_or_echo(payload, output_path, label="OSCAL Assessment Results")


def _write_or_echo(payload: str, output_path: Path | None, *, label: str) -> None:
    if output_path is None:
        typer.echo(payload)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload + "\n", encoding="utf-8")
    console.print(f"[green]{label}[/green] → {output_path}")
