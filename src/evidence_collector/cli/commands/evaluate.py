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
from evidence_collector.exporters import export_html, export_json, export_markdown


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
        evidence = EVIDENCE_ADAPTER.validate_python(data)
    except (ValidationError, json.JSONDecodeError) as exc:
        console.print(f"[red]Invalid evidence file {evidence_path}:[/red] {exc}")
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

    app_ = build_application(application, repository, environment, owner_team)
    release = build_release(release_id, commit_sha, branch)
    bundle, _ = build_bundle(app_, release, list(evidence), catalog_path=catalog_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = export_json(bundle, output_dir / "bundle.json")
    markdown_path = export_markdown(bundle, output_dir / "report.md")
    html_path = export_html(bundle, output_dir / "summary.html")

    result = BundleBuildResult(
        bundle=bundle,
        json_path=json_path,
        markdown_path=markdown_path,
        html_path=html_path,
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
