"""``sdlc-evidence collect`` — walk local dirs and emit normalized evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.cli._builders import build_release
from evidence_collector.cli._state import EVIDENCE_ADAPTER, console
from evidence_collector.exporters._atomic import write_atomic


def register(app: typer.Typer) -> None:
    """Attach the ``collect`` command to ``app``."""

    @app.command("collect")
    def cmd_collect(
        release_id: Annotated[str, typer.Option("--release-id", help="Release identifier")],
        commit_sha: Annotated[str, typer.Option("--commit-sha", help="Commit SHA for the release")],
        output_path: Annotated[
            Path, typer.Option("--output", help="Where to write the evidence JSON list")
        ] = Path("evidence.json"),
        branch: Annotated[str, typer.Option(help="Branch name")] = "main",
        artifacts_dir: Annotated[
            list[Path] | None,
            typer.Option(
                "--artifacts-dir",
                help="Directory with raw evidence artifacts (can be given multiple times)",
            ),
        ] = None,
        attestations_dir: Annotated[
            list[Path] | None,
            typer.Option(
                "--attestations-dir",
                help="Directory with YAML/JSON attestations (can be given multiple times)",
            ),
        ] = None,
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
        # Envelope, not a bare list. The bare list had nowhere to carry the
        # collection errors, so the documented `collect` -> `evaluate` split
        # dropped them at the boundary: the console warned, the file did not
        # record it, and the resulting bundle asserted `collection_errors: []`
        # — a positive claim that nothing had failed to parse.
        #
        # `evaluate` still accepts a bare list, so files written by earlier
        # versions keep working.
        payload = {
            "evidence": EVIDENCE_ADAPTER.dump_python(report.evidence, mode="json"),
            "collection_errors": [
                {"path": str(error.path), "reason": error.reason} for error in report.errors
            ],
        }
        write_atomic(output_path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        console.print(
            f"[green]Collected[/green] {len(report.evidence)} evidence records → {output_path}"
        )
        if report.errors:
            console.print("[yellow]Collection warnings:[/yellow]")
            for error in report.errors:
                console.print(f"  - {error.path}: {error.reason}")
