"""Rich rendering helpers shared across commands.

Each helper checks :func:`is_json_logs` and either emits NDJSON via
``emit_event`` or renders a Rich table. Keeping these in one place means
the human and machine-readable surfaces stay aligned automatically.
"""

from __future__ import annotations

from rich.table import Table

from evidence_collector.application.orchestrator import BundleBuildResult
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs


def render_summary(result: BundleBuildResult) -> None:
    """Render the release-readiness summary as a Rich table or NDJSON event."""
    summary = result.bundle.summary

    if is_json_logs():
        emit_event(
            "bundle_built",
            bundle_id=result.bundle.bundle_id,
            release_status=summary.release_status.value,
            coverage=summary.evidence_coverage_score,
            confidence=summary.confidence_score,
            controls_met=summary.controls_met,
            controls_partial=summary.controls_partial,
            controls_missing=summary.controls_missing,
            controls_waived=summary.controls_waived,
            controls_not_applicable=summary.controls_not_applicable,
            evidence_count=len(result.bundle.evidence),
            missing_critical_evidence=list(summary.missing_critical_evidence),
            bundle_json=str(result.json_path) if result.json_path else None,
            report_md=str(result.markdown_path) if result.markdown_path else None,
            summary_html=str(result.html_path) if result.html_path else None,
        )
        return

    table = Table(title="Release readiness summary", show_header=False, box=None)
    table.add_row("Bundle ID", result.bundle.bundle_id)
    table.add_row("Release status", f"[bold]{summary.release_status.value}[/bold]")
    table.add_row(
        "Scores",
        f"coverage={summary.evidence_coverage_score} confidence={summary.confidence_score}",
    )
    table.add_row(
        "Controls",
        f"met={summary.controls_met} partial={summary.controls_partial} "
        f"missing={summary.controls_missing} waived={summary.controls_waived} "
        f"n/a={summary.controls_not_applicable}",
    )
    table.add_row(
        "Evidence count",
        str(len(result.bundle.evidence)),
    )
    if summary.missing_critical_evidence:
        table.add_row(
            "Missing critical",
            ", ".join(summary.missing_critical_evidence),
        )
    console.print(table)
    if result.json_path:
        console.print(f"[green]bundle.json[/green]  → {result.json_path}")
    if result.markdown_path:
        console.print(f"[green]report.md[/green]    → {result.markdown_path}")
    if result.html_path:
        console.print(f"[green]summary.html[/green] → {result.html_path}")


def render_collection_errors(result: BundleBuildResult) -> None:
    """Surface collection errors either as NDJSON events or a Rich warning block."""
    if result.collection_report is None:
        return
    errors = result.collection_report.errors
    if not errors:
        return
    if is_json_logs():
        for error in errors:
            emit_event("collection_error", path=str(error.path), reason=error.reason)
        return
    console.print("[yellow]Collection warnings:[/yellow]")
    for error in errors:
        console.print(f"  - {error.path}: {error.reason}")
