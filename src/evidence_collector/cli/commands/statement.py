"""``sdlc-evidence statement`` — wrap a bundle as an in-toto Statement v1.

Produces an in-toto Statement file that can be signed with cosign
keyless and consumed by GUAC, Kyverno, OPA Gatekeeper, and any other
Sigstore-aware verifier. Optionally emits an unsigned DSSE envelope
for callers that want to hand the file straight to a signing pipeline.

This command never signs anything — keeping private keys out of the
collector is the right boundary for an evidence-collection tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, cast

import typer
from pydantic import ValidationError

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters.intoto import (
    PredicateType,
    build_dsse_envelope,
    build_statement,
    predicate_type_url,
)


def register(app: typer.Typer) -> None:
    """Attach the ``statement`` command to ``app``."""

    @app.command("statement")
    def cmd_statement(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                exists=True,
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json to wrap.",
            ),
        ],
        output: Annotated[
            Path,
            typer.Option(
                "--output",
                "-o",
                help="Where to write the in-toto Statement JSON.",
            ),
        ] = Path("statement.intoto.json"),
        dsse_envelope: Annotated[
            bool,
            typer.Option(
                "--dsse-envelope/--no-dsse-envelope",
                help=(
                    "Also write an unsigned DSSE envelope (.dsse.json) "
                    "next to the Statement. The envelope is ready for "
                    "external signing (cosign sign-blob, custom KMS)."
                ),
            ),
        ] = False,
        predicate_type: Annotated[
            str,
            typer.Option(
                "--predicate-type",
                help=(
                    "predicateType variant: 'evidence-bundle' (default, "
                    "project-native), 'witness' (Witness-compatible custom "
                    "attestation), or 'slsa-provenance' "
                    "(SLSA Provenance v1 URI)."
                ),
            ),
        ] = "evidence-bundle",
    ) -> None:
        """Wrap BUNDLE_PATH as an in-toto Statement v1 JSON document."""
        if predicate_type not in {"evidence-bundle", "witness", "slsa-provenance"}:
            message = (
                f"Unknown --predicate-type '{predicate_type}'. Valid values: "
                "evidence-bundle, witness, slsa-provenance."
            )
            if is_json_logs():
                emit_event("statement_failed", bundle=str(bundle_path), reason=message)
            else:
                console.print(f"[red]{message}[/red]")
            raise typer.Exit(code=2)
        try:
            raw = json.loads(bundle_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if is_json_logs():
                emit_event("statement_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Could not read {bundle_path}:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        try:
            bundle = EvidenceBundle.model_validate(raw)
        except ValidationError as exc:
            if is_json_logs():
                emit_event("statement_failed", bundle=str(bundle_path), reason=str(exc))
            else:
                console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
            raise typer.Exit(code=2) from exc

        # Safe cast: predicate_type was validated against the literal
        # set above; mypy needs the explicit narrowing.
        predicate_type_literal = cast(PredicateType, predicate_type)
        statement = build_statement(bundle, predicate_type=predicate_type_literal)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(statement, indent=2, sort_keys=False), encoding="utf-8")

        envelope_path: Path | None = None
        if dsse_envelope:
            envelope = build_dsse_envelope(statement)
            envelope_path = output.with_suffix(".dsse.json")
            envelope_path.write_text(
                json.dumps(envelope, indent=2, sort_keys=False), encoding="utf-8"
            )

        emitted_predicate_url = predicate_type_url(predicate_type_literal)
        if is_json_logs():
            emit_event(
                "statement_emitted",
                bundle=str(bundle_path),
                statement=str(output),
                envelope=str(envelope_path) if envelope_path else None,
                predicate_type=emitted_predicate_url,
                predicate_type_name=predicate_type,
            )
        else:
            console.print(
                f"[green]in-toto Statement[/green] · "
                f"predicateType={emitted_predicate_url} → {output}"
            )
            if envelope_path is not None:
                console.print(f"[green]DSSE envelope (unsigned)[/green] → {envelope_path}")
