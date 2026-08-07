"""``sdlc-evidence verify`` — recompute a bundle's structural SHA-256.

The collector ships a deterministic ``bundle.json`` per release. Once
downstream consumers receive that file (via release artefact, OCI
attestation, OSCAL pipeline, etc.) they need a way to confirm the file
they have is structurally identical to the one the producer signed.

The ``verify`` command does exactly that: it strips the documented
volatile fields, recomputes the structural SHA-256 and prints it. When
the user passes ``--expected SHA``, the command also exits with code 2
on drift so it can be wired into CI as a hard gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.application.integrity import structural_sha256
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs


def register(app: typer.Typer) -> None:
    """Attach the ``verify`` command to ``app``."""

    @app.command("verify")
    def cmd_verify(
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
                help="Path to the bundle.json to verify",
            ),
        ],
        expected: Annotated[
            str | None,
            typer.Option(
                "--expected",
                help=(
                    "Expected structural SHA-256. When provided, the command "
                    "exits with code 2 on mismatch."
                ),
            ),
        ] = None,
    ) -> None:
        """Recompute the structural SHA-256 of a bundle.json.

        Without ``--expected``, prints the digest and exits 0.
        With ``--expected``, exits 0 on match and 2 on drift.
        Malformed JSON or unreadable files exit with code 3.
        """
        try:
            actual = structural_sha256(bundle_path)
        except (OSError, json.JSONDecodeError) as exc:
            if is_json_logs():
                emit_event(
                    "verify_failed",
                    bundle=str(bundle_path),
                    reason=str(exc),
                )
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc

        if expected is None:
            if is_json_logs():
                emit_event("verify_computed", bundle=str(bundle_path), sha256=actual)
            else:
                console.print(actual)
            raise typer.Exit(code=0)

        expected_norm = expected.strip().lower()
        match = actual == expected_norm
        if is_json_logs():
            emit_event(
                "verify_result",
                bundle=str(bundle_path),
                sha256=actual,
                expected=expected_norm,
                match=match,
            )
        else:
            if match:
                console.print(f"[green]match[/green] · {actual}")
            else:
                console.print(f"[red]drift[/red] · actual={actual} · expected={expected_norm}")

        raise typer.Exit(code=0 if match else 2)
