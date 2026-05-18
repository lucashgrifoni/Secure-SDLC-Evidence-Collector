"""``sdlc-evidence doctor`` — pre-flight environment health check."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer
from rich.table import Table

from evidence_collector.cli._state import console
from evidence_collector.domain.models import EvidenceBundle


def doctor_checks() -> list[tuple[str, bool, str]]:
    """Run the health checks. Returns (label, ok, detail) per check.

    Pure function so it can be unit-tested without invoking Typer.
    """
    results: list[tuple[str, bool, str]] = []

    # Python version: the package declares requires-python >= 3.12.
    py_ok = sys.version_info >= (3, 12)
    results.append(
        (
            "Python version",
            py_ok,
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} "
            f"({'>=3.12' if py_ok else 'requires >=3.12'})",
        )
    )

    # Required runtime dependencies. We import them lazily so a partial
    # install fails loudly instead of crashing every command silently.
    deps = ["typer", "pydantic", "jinja2", "yaml", "httpx", "rich", "defusedxml"]
    for module in deps:
        try:
            __import__(module)
            results.append((f"Import: {module}", True, "ok"))
        except ImportError as exc:  # pragma: no cover - exercised only on broken installs
            results.append((f"Import: {module}", False, str(exc)))

    # Optional credentials. These are not required for local runs, only
    # when collecting from the corresponding SCM.
    for token_var, label in (
        ("GITHUB_TOKEN", "GitHub token (optional)"),
        ("GITLAB_TOKEN", "GitLab token (optional)"),
    ):
        present = bool(os.environ.get(token_var))
        # Optional checks always count as "ok" — we just report status.
        detail = "present (will be used)" if present else "absent (collectors will skip SCM)"
        results.append((label, True, detail))

    # Schema export sanity. Confirms Pydantic + the bundle model are in
    # a healthy state without writing anything to the user's tree.
    try:
        EvidenceBundle.model_json_schema()
        results.append(("Schema export", True, "EvidenceBundle.model_json_schema() ok"))
    except Exception as exc:  # pragma: no cover - guard against future Pydantic regressions
        results.append(("Schema export", False, f"{type(exc).__name__}: {exc}"))

    # Write permissions. We never write outside an explicit --output-dir,
    # but it is useful to confirm the user's cwd is writable.
    try:
        with tempfile.NamedTemporaryFile(dir=Path.cwd(), delete=True):
            pass
        results.append(("Write permission in cwd", True, str(Path.cwd())))
    except OSError as exc:
        results.append(("Write permission in cwd", False, f"{type(exc).__name__}: {exc}"))

    # Optional cosign — used by the release workflow for keyless signing.
    cosign_path = shutil.which("cosign")
    cosign_detail = cosign_path or "not installed (only needed for signed releases)"
    results.append(("cosign (optional)", True, cosign_detail))

    return results


def register(app: typer.Typer) -> None:
    """Attach the ``doctor`` command to ``app``."""

    @app.command("doctor")
    def cmd_doctor(
        json_output: Annotated[
            bool,
            typer.Option("--json", help="Emit results as JSON instead of a Rich table"),
        ] = False,
    ) -> None:
        """Check the local environment is ready to run the collector.

        Exits 0 when every required check passes (optional ones never fail);
        exits 1 when any required check fails. Designed to be wired into CI
        or as a pre-flight step in operator runbooks.
        """
        results = doctor_checks()
        failed = [(label, detail) for label, ok, detail in results if not ok]

        if json_output:
            payload = [
                {"check": label, "ok": ok, "detail": detail} for label, ok, detail in results
            ]
            typer.echo(json.dumps({"checks": payload, "failed": len(failed)}, indent=2))
        else:
            table = Table(title="sdlc-evidence doctor", show_header=True)
            table.add_column("Check")
            table.add_column("Status")
            table.add_column("Detail", overflow="fold")
            for label, ok, detail in results:
                status = "[green]ok[/green]" if ok else "[red]fail[/red]"
                table.add_row(label, status, detail)
            console.print(table)
            if failed:
                console.print(f"[red]{len(failed)} required check(s) failed.[/red]")
            else:
                console.print("[green]All required checks passed.[/green]")

        if failed:
            raise typer.Exit(code=1)
