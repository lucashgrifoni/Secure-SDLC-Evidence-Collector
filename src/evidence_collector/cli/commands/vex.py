"""``sdlc-evidence vex`` — emit an OpenVEX document from a bundle.json.

Reads an existing bundle and writes a single OpenVEX 0.2.0 JSON
document that restates the bundle's exploitability story per CVE.
Designed to live next to the bundle in a release artifact set so
downstream consumers (e.g. EU CRA evidence packs) can ingest VEX
without reverse-engineering the bundle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_atomic
from evidence_collector.exporters.vex import (
    MergeConflictPolicy,
    VexMergeConflictError,
    build_openvex,
    merge_consumed_vex,
)
from evidence_collector.parsers.vex import parse_vex


def register(app: typer.Typer) -> None:
    """Attach the ``vex`` command to ``app``."""

    @app.command("vex")
    def cmd_vex(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                # No exists=True: Click validates it BEFORE the command body and
                # raises UsageError -> exit 2, the not_ready code. The body below
                # already catches OSError and exits EXIT_INPUT_ERROR, which is what
                # the README promises for every input failure.
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json to translate into OpenVEX.",
            ),
        ],
        output: Annotated[
            Path,
            typer.Option(
                "--output",
                "-o",
                help="Where to write the OpenVEX JSON document.",
            ),
        ] = Path("openvex.json"),
        consume: Annotated[
            list[Path] | None,
            typer.Option(
                "--consume",
                help=(
                    "Path to an external VEX document (OpenVEX / CycloneDX VEX / CSAF) "
                    "to merge into the bundle-derived statements. Repeatable."
                ),
            ),
        ] = None,
        policy: Annotated[
            str,
            typer.Option(
                "--policy",
                help=(
                    "Conflict policy when --consume sources disagree with the bundle: "
                    "first-wins | last-wins | fail. Default: last-wins."
                ),
            ),
        ] = "last-wins",
    ) -> None:
        """Emit an OpenVEX 0.2.0 document derived from BUNDLE_PATH."""
        if policy not in {p.value for p in MergeConflictPolicy}:
            raise typer.BadParameter(
                f"--policy must be one of first-wins, last-wins, fail; got '{policy}'."
            )
        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if is_json_logs():
                emit_event("vex_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
        try:
            bundle = EvidenceBundle.model_validate(raw)
        except ValidationError as exc:
            if is_json_logs():
                emit_event("vex_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        document = build_openvex(bundle)

        consumed_count = 0
        if consume:
            consumed_statements = []
            for path in consume:
                consumed_statements.extend(parse_vex(path))
            consumed_count = len(consumed_statements)
            try:
                document = merge_consumed_vex(
                    document,
                    bundle,
                    consumed_statements,
                    policy=MergeConflictPolicy(policy),
                )
            except VexMergeConflictError as exc:
                if is_json_logs():
                    emit_event(
                        "vex_failed", bundle=str(bundle_path), reason=str(exc), policy=policy
                    )
                else:
                    console.print(f"[red]VEX merge conflict:[/red] {exc}")
                raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        write_atomic(output, json.dumps(document, indent=2, sort_keys=False))

        statements = document.get("statements", [])
        if is_json_logs():
            emit_event(
                "vex_emitted",
                bundle=str(bundle_path),
                output=str(output),
                statements=len(statements),
                consumed=consumed_count,
                policy=policy,
            )
        else:
            console.print(
                f"[green]OpenVEX[/green] · {len(statements)} statement(s)"
                + (
                    f" (merged {consumed_count} consumed, policy={policy})"
                    if consumed_count
                    else ""
                )
                + f" → {output}"
            )
