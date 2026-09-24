"""``sdlc-evidence compare`` — semantic diff between two bundles."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.application.compare import compare_bundles, load_bundle
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR, UNREADABLE_INPUT
from evidence_collector.cli._state import console
from evidence_collector.domain.enums import ReleaseStatus

_FORMATS = ("table", "json")

# Worse status ⇒ higher rank, mirroring cli/_exit_codes.py so the arrow and
# the exit code can never disagree about what "worse" means.
_RELEASE_STATUS_RANK: dict[ReleaseStatus, int] = {
    ReleaseStatus.READY: 0,
    ReleaseStatus.CONDITIONAL: 1,
    ReleaseStatus.NOT_READY: 2,
}


def _status_delta(before: ReleaseStatus, after: ReleaseStatus) -> str:
    """Direction of travel between two release statuses.

    This used to be ``"⬆" if after == READY else ""``, which never looked at
    ``before``: a release regressing from ready to not_ready rendered a blank
    cell, while comparing a bundle against itself rendered an improvement
    arrow. The table is the output meant for a PR comment, so the reviewer got
    the wrong signal on precisely the most serious change.
    """
    if _RELEASE_STATUS_RANK[after] < _RELEASE_STATUS_RANK[before]:
        return "⬆ improved"
    if _RELEASE_STATUS_RANK[after] > _RELEASE_STATUS_RANK[before]:
        return "⬇ regressed"
    return "="


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
        # An unrecognized --format silently fell back to the Rich table, so a
        # script asking for JSON received unicode box-drawing characters and
        # exit 0. Reject it the way --risk-mode and --policy already do.
        normalized_format = output_format.lower()
        if normalized_format not in _FORMATS:
            raise typer.BadParameter(
                f"--format must be one of {list(_FORMATS)}; got '{output_format}'."
            )
        try:
            baseline = load_bundle(before)
            candidate = load_bundle(after)
        except UNREADABLE_INPUT as exc:
            console.print(f"[red]Could not load bundles:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        comparison = compare_bundles(baseline, candidate)
        if normalized_format == "json":
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
            _status_delta(comparison.before_release_status, comparison.after_release_status),
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

        # EPSS scores are not comparable across model versions: v5 re-fits
        # the model rather than re-scoring under the old one, so exposure
        # can appear to move when only the model changed. Saying so is the
        # difference between a diff a reader can act on and one that
        # quietly misleads.
        if comparison.epss_model_drift:
            console.print(
                "[yellow]EPSS model drift:[/yellow] baseline used "
                f"{', '.join(comparison.before_epss_model_versions)}; candidate used "
                f"{', '.join(comparison.after_epss_model_versions)}. "
                "EPSS scores are not comparable across model versions — treat any "
                "score or risk movement as unexplained until re-enriched under a "
                "single model."
            )
