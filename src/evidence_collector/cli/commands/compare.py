"""``sdlc-evidence compare`` — semantic diff between two bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.table import Table

from evidence_collector.application.compare import compare_bundles, load_bundle
from evidence_collector.cli._state import console
from evidence_collector.domain.enums import ReleaseStatus


def register(app: typer.Typer) -> None:
    """Attach the ``compare`` command to ``app``."""

    @app.command("compare")
    def cmd_compare(
        before: Annotated[Path, typer.Argument(help="Path to the baseline bundle.json")],
        after: Annotated[Path, typer.Argument(help="Path to the new bundle.json")],
        output_format: Annotated[
            str, typer.Option("--format", help="Output format: table or json")
        ] = "table",
    ) -> None:
        """Compare two bundle.json files and summarize what changed."""
        try:
            baseline = load_bundle(before)
            candidate = load_bundle(after)
        except (ValidationError, json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Could not load bundles:[/red] {exc}")
            raise typer.Exit(code=3) from exc

        comparison = compare_bundles(baseline, candidate)
        if output_format.lower() == "json":
            console.print_json(data=comparison.to_dict())
            return

        table = Table(title=f"Bundle diff: {baseline.bundle_id} → {candidate.bundle_id}")
        table.add_column("Metric")
        table.add_column("Before")
        table.add_column("After")
        table.add_column("Delta")
        table.add_row(
            "release_status",
            comparison.before_release_status.value,
            comparison.after_release_status.value,
            "⬆" if comparison.after_release_status == ReleaseStatus.READY else "",
        )
        table.add_row(
            "coverage",
            str(baseline.summary.evidence_coverage_score),
            str(candidate.summary.evidence_coverage_score),
            f"{comparison.coverage_delta:+d}",
        )
        table.add_row(
            "confidence",
            str(baseline.summary.confidence_score),
            str(candidate.summary.confidence_score),
            f"{comparison.confidence_delta:+d}",
        )
        console.print(table)

        control_table = Table(title="Control-level diff")
        control_table.add_column("Control ID")
        control_table.add_column("Before")
        control_table.add_column("After")
        control_table.add_column("Change")
        for delta in comparison.control_deltas:
            control_table.add_row(
                delta.control_id,
                delta.before.value if delta.before else "-",
                delta.after.value if delta.after else "-",
                delta.category,
            )
        console.print(control_table)
