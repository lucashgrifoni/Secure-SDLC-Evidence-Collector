"""``sdlc-evidence evaluate`` — turn an evidence list into a bundle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.application.orchestrator import BundleBuildResult, build_bundle
from evidence_collector.cli._builders import build_application, build_release
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR, fail_on_exit_code, validate_fail_on
from evidence_collector.cli._render import render_summary
from evidence_collector.cli._state import EVIDENCE_ADAPTER, console
from evidence_collector.domain.models import CollectionError
from evidence_collector.exporters import export_report_set


def evaluate(
    evidence_path: Path,
    application: str,
    repository: str,
    release_id: str,
    commit_sha: str,
    output_dir: Path,
    branch: str,
    environment: str,
    owner_team: str | None,
    catalog_path: Path | None,
    fail_on: str,
) -> None:
    """Reusable core for ``evaluate`` and the legacy ``bundle`` alias."""
    fail_on = validate_fail_on(fail_on)
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
        # `collect` writes an envelope carrying the evidence and the inputs it
        # could not read. A bare list is what earlier versions wrote and is
        # still accepted — but it can say nothing about failed inputs, so a
        # bundle built from one must not claim there were none.
        if isinstance(data, dict):
            raw_evidence = data.get("evidence", [])
            raw_errors = data.get("collection_errors", [])
        else:
            raw_evidence = data
            raw_errors = []
        evidence = EVIDENCE_ADAPTER.validate_python(raw_evidence)
        collection_errors = [CollectionError.model_validate(entry) for entry in raw_errors]
    except (ValidationError, json.JSONDecodeError) as exc:
        console.print(f"[red]Invalid evidence file {evidence_path}:[/red] {exc}")
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

    if collection_errors:
        console.print("[yellow]Collection warnings carried from the evidence file:[/yellow]")
        for error in collection_errors:
            console.print(f"  - {error.path}: {error.reason}")

    app_ = build_application(application, repository, environment, owner_team)
    release = build_release(release_id, commit_sha, branch)
    bundle, _ = build_bundle(
        app_,
        release,
        list(evidence),
        catalog_path=catalog_path,
        collection_errors=collection_errors,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    reports = export_report_set(bundle, output_dir)

    result = BundleBuildResult(
        bundle=bundle,
        json_path=reports.json_path,
        markdown_path=reports.markdown_path,
        html_path=reports.html_path,
    )
    render_summary(result)
    raise typer.Exit(code=fail_on_exit_code(bundle.summary.release_status, fail_on))


def register(app: typer.Typer) -> None:
    """Attach the ``evaluate`` command to ``app``."""

    @app.command("evaluate")
    def cmd_evaluate(
        evidence_path: Annotated[
            Path, typer.Option("--evidence", help="Path to an evidence JSON list")
        ],
        application: Annotated[str, typer.Option(help="Application name")],
        repository: Annotated[str, typer.Option(help="Repository reference")],
        release_id: Annotated[str, typer.Option("--release-id", help="Release identifier")],
        commit_sha: Annotated[str, typer.Option("--commit-sha", help="Commit SHA for the release")],
        output_dir: Annotated[
            Path, typer.Option("--output-dir", help="Directory where bundle outputs are written")
        ] = Path("output"),
        branch: Annotated[str, typer.Option(help="Branch name")] = "main",
        environment: Annotated[
            str, typer.Option(help="Target environment recorded in the bundle as stated fact")
        ] = "production",
        owner_team: Annotated[
            str | None, typer.Option(help="Owning team recorded on the release context")
        ] = None,
        catalog_path: Annotated[
            Path | None,
            typer.Option(
                "--catalog", help="Control catalog: a path, or the bare name of a bundled catalog"
            ),
        ] = None,
        fail_on: Annotated[
            str,
            typer.Option(
                "--fail-on",
                help="Exit non-zero when release_status reaches this severity: ready|conditional|not_ready",
            ),
        ] = "not_ready",
    ) -> None:
        """Evaluate an existing evidence list and produce the full bundle outputs."""
        evaluate(
            evidence_path=evidence_path,
            application=application,
            repository=repository,
            release_id=release_id,
            commit_sha=commit_sha,
            output_dir=output_dir,
            branch=branch,
            environment=environment,
            owner_team=owner_team,
            catalog_path=catalog_path,
            fail_on=fail_on,
        )
