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
        evidence_path: Annotated[Path, typer.Option("--evidence")],
        application: Annotated[str, typer.Option()],
        repository: Annotated[str, typer.Option()],
        release_id: Annotated[str, typer.Option("--release-id")],
        commit_sha: Annotated[str, typer.Option("--commit-sha")],
        output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("output"),
        branch: Annotated[str, typer.Option()] = "main",
        environment: Annotated[str, typer.Option()] = "production",
        catalog_path: Annotated[Path | None, typer.Option("--catalog")] = None,
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
