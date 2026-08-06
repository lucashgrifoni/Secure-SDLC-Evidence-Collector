"""``sdlc-evidence bundle`` — naming alias of ``evaluate`` kept for compat."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli.commands.evaluate import evaluate


def register(app: typer.Typer) -> None:
    """Attach the ``bundle`` alias command to ``app``."""

    @app.command("bundle")
    def cmd_bundle(
        evidence_path: Annotated[
            Path, typer.Option("--evidence", help="Path to the evidence JSON produced by `collect`")
        ],
        application: Annotated[str, typer.Option(help="Application name")],
        repository: Annotated[str, typer.Option(help="Repository reference, e.g. owner/repo")],
        release_id: Annotated[str, typer.Option("--release-id", help="Release identifier")],
        commit_sha: Annotated[str, typer.Option("--commit-sha", help="Commit SHA for the release")],
        output_dir: Annotated[
            Path, typer.Option("--output-dir", help="Directory where bundle outputs are written")
        ] = Path("output"),
        branch: Annotated[str, typer.Option(help="Branch name")] = "main",
        environment: Annotated[
            str, typer.Option(help="Target environment recorded in the bundle as stated fact")
        ] = "production",
        catalog_path: Annotated[
            Path | None,
            typer.Option(
                "--catalog", help="Control catalog: a path, or the bare name of a bundled catalog"
            ),
        ] = None,
    ) -> None:
        """Alias of `evaluate` kept for naming compatibility with the plan doc."""
        evaluate(
            evidence_path=evidence_path,
            application=application,
            repository=repository,
            release_id=release_id,
            commit_sha=commit_sha,
            output_dir=output_dir,
            branch=branch,
            environment=environment,
            owner_team=None,
            catalog_path=catalog_path,
            fail_on="not_ready",
        )
