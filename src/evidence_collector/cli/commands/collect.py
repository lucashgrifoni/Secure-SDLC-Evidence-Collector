"""``sdlc-evidence collect`` — walk local dirs and emit normalized evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli._builders import build_release
from evidence_collector.cli._state import EVIDENCE_ADAPTER, console


def register(app: typer.Typer) -> None:
    """Attach the ``collect`` command to ``app``."""

    @app.command("collect")
    def cmd_collect(
        release_id: Annotated[str, typer.Option("--release-id")],
        commit_sha: Annotated[str, typer.Option("--commit-sha")],
        output_path: Annotated[
            Path, typer.Option("--output", help="Where to write the evidence JSON list")
        ] = Path("evidence.json"),
        branch: Annotated[str, typer.Option(help="Branch name")] = "main",
        artifacts_dir: Annotated[list[Path] | None, typer.Option("--artifacts-dir")] = None,
        attestations_dir: Annotated[list[Path] | None, typer.Option("--attestations-dir")] = None,
    ) -> None:
        """Collect evidence from local directories and write the normalized list."""
        release = build_release(release_id, commit_sha, branch)
        from evidence_collector.collectors.local import LocalArtifactCollector

        collector = LocalArtifactCollector(
            release=release,
            artifacts_dirs=list(artifacts_dir) if artifacts_dir else [],
            attestations_dirs=list(attestations_dir) if attestations_dir else [],
        )
        report = collector.collect()
        payload = EVIDENCE_ADAPTER.dump_python(report.evidence, mode="json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        console.print(
            f"[green]Collected[/green] {len(report.evidence)} evidence records → {output_path}"
        )
        if report.errors:
            console.print("[yellow]Collection warnings:[/yellow]")
            for error in report.errors:
                console.print(f"  - {error.path}: {error.reason}")
