"""Typer CLI for the Secure SDLC Evidence Collector.

The CLI is the primary interface for the MVP. It exposes four commands:

- ``collect``  — walk local directories and output a raw evidence JSON list
- ``evaluate`` — take a raw evidence JSON list and produce the bundle
- ``bundle``   — alias for ``evaluate`` that mirrors the planning doc
- ``run``      — full pipeline (collect + evaluate + export)

GitHub integration is opt-in via ``--pull-request`` / ``--workflow-run`` on
the ``run`` command. The CLI refuses to write outside the provided
``--output-dir`` and does not log tokens.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import TypeAdapter, ValidationError
from rich.console import Console
from rich.table import Table

from evidence_collector import __version__
from evidence_collector.application.compare import compare_bundles, load_bundle
from evidence_collector.application.orchestrator import (
    BundleBuildResult,
    build_bundle,
    run_pipeline,
)
from evidence_collector.collectors.github import GitHubCollector, GitHubCollectorConfig
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import (
    Application,
    EvidenceBundle,
    NormalizedEvidence,
    ReleaseContext,
)
from evidence_collector.exporters import export_html, export_json, export_markdown
from evidence_collector.parsers import parse_exception
from evidence_collector.parsers._common import ParseError

app = typer.Typer(
    name="sdlc-evidence",
    help="Secure SDLC Evidence Collector — collect, evaluate and bundle release evidence.",
    no_args_is_help=False,
    add_completion=False,
)
console = Console()

_EVIDENCE_ADAPTER: TypeAdapter[list[NormalizedEvidence]] = TypeAdapter(list[NormalizedEvidence])


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s %(message)s",
    )


def _build_application(
    name: str,
    repository: str,
    environment: str,
    owner_team: str | None,
) -> Application:
    return Application(
        name=name,
        repository=repository,
        environment=environment,
        owner_team=owner_team,
    )


def _build_release(
    release_id: str,
    commit_sha: str,
    branch: str,
    pipeline_run_id: str | None,
    build_id: str | None,
    artifact_digest: str | None,
    tag: str | None,
) -> ReleaseContext:
    return ReleaseContext(
        release_id=release_id,
        commit_sha=commit_sha,
        branch=branch,
        pipeline_run_id=pipeline_run_id,
        build_id=build_id,
        artifact_digest=artifact_digest,
        tag=tag,
    )


def _exit_code_for_status(status: ReleaseStatus) -> int:
    if status == ReleaseStatus.NOT_READY:
        return 2
    if status == ReleaseStatus.CONDITIONAL:
        return 1
    return 0


def _render_summary(result: BundleBuildResult) -> None:
    summary = result.bundle.summary
    table = Table(title="Release readiness summary", show_header=False, box=None)
    table.add_row("Bundle ID", result.bundle.bundle_id)
    table.add_row("Release status", f"[bold]{summary.release_status.value}[/bold]")
    table.add_row(
        "Scores",
        f"coverage={summary.evidence_coverage_score} confidence={summary.confidence_score}",
    )
    table.add_row(
        "Controls",
        f"met={summary.controls_met} partial={summary.controls_partial} "
        f"missing={summary.controls_missing} waived={summary.controls_waived} "
        f"n/a={summary.controls_not_applicable}",
    )
    table.add_row(
        "Evidence count",
        str(len(result.bundle.evidence)),
    )
    if summary.missing_critical_evidence:
        table.add_row(
            "Missing critical",
            ", ".join(summary.missing_critical_evidence),
        )
    console.print(table)
    if result.json_path:
        console.print(f"[green]bundle.json[/green]  → {result.json_path}")
    if result.markdown_path:
        console.print(f"[green]report.md[/green]    → {result.markdown_path}")
    if result.html_path:
        console.print(f"[green]summary.html[/green] → {result.html_path}")


def _render_collection_errors(result: BundleBuildResult) -> None:
    if result.collection_report is None:
        return
    errors = result.collection_report.errors
    if not errors:
        return
    console.print("[yellow]Collection warnings:[/yellow]")
    for error in errors:
        console.print(f"  - {error.path}: {error.reason}")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Enable verbose logging")
    ] = False,
    version: Annotated[bool, typer.Option("--version", help="Print version and exit")] = False,
) -> None:
    """Secure SDLC Evidence Collector CLI."""
    if version:
        typer.echo(__version__)
        raise typer.Exit(code=0)
    _configure_logging(verbose)
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)


@app.command("run")
def cmd_run(
    application: Annotated[str, typer.Option(help="Application name")],
    repository: Annotated[str, typer.Option(help="Repository reference, e.g. owner/repo")],
    release_id: Annotated[str, typer.Option("--release-id", help="Release identifier")],
    commit_sha: Annotated[str, typer.Option("--commit-sha", help="Commit SHA for the release")],
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", help="Directory where bundle outputs are written"),
    ] = Path("output"),
    branch: Annotated[str, typer.Option(help="Branch name")] = "main",
    environment: Annotated[str, typer.Option(help="Target environment")] = "production",
    owner_team: Annotated[str | None, typer.Option(help="Owner team")] = None,
    pipeline_run_id: Annotated[str | None, typer.Option("--pipeline-run-id")] = None,
    build_id: Annotated[str | None, typer.Option("--build-id")] = None,
    artifact_digest: Annotated[str | None, typer.Option("--artifact-digest")] = None,
    tag: Annotated[str | None, typer.Option("--tag")] = None,
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
    exceptions_dir: Annotated[
        list[Path] | None,
        typer.Option(
            "--exceptions-dir",
            help="Directory with YAML/JSON exception (waiver) files",
        ),
    ] = None,
    catalog_path: Annotated[
        Path | None,
        typer.Option("--catalog", help="Override the default control catalog YAML"),
    ] = None,
    pull_request: Annotated[
        int | None,
        typer.Option("--pull-request", help="GitHub PR number to pull code-review evidence from"),
    ] = None,
    workflow_run: Annotated[
        int | None,
        typer.Option("--workflow-run", help="GitHub Actions run ID to record"),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Exit non-zero when release_status reaches this severity: ready|conditional|not_ready",
        ),
    ] = "not_ready",
) -> None:
    """Run the full pipeline: collect, evaluate, and export the bundle."""
    app_ = _build_application(application, repository, environment, owner_team)
    release = _build_release(
        release_id, commit_sha, branch, pipeline_run_id, build_id, artifact_digest, tag
    )

    extra_evidence: list[NormalizedEvidence] = []
    if pull_request is not None or workflow_run is not None:
        config = GitHubCollectorConfig.from_env(repository=repository)
        with GitHubCollector(config=config, release=release) as gh:
            if pull_request is not None:
                extra_evidence.append(gh.collect_pull_request(pull_request))
            if workflow_run is not None:
                extra_evidence.append(gh.collect_workflow_run(workflow_run))

    result = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=list(artifacts_dir) if artifacts_dir else [],
        attestations_dirs=list(attestations_dir) if attestations_dir else [],
        exceptions_dirs=list(exceptions_dir) if exceptions_dir else [],
        extra_evidence=extra_evidence,
        output_dir=output_dir,
        catalog_path=catalog_path,
    )
    _render_summary(result)
    _render_collection_errors(result)

    raise typer.Exit(code=_fail_on_exit_code(result.bundle.summary.release_status, fail_on))


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
    release = _build_release(release_id, commit_sha, branch, None, None, None, None)
    from evidence_collector.collectors.local import LocalArtifactCollector

    collector = LocalArtifactCollector(
        release=release,
        artifacts_dirs=list(artifacts_dir) if artifacts_dir else [],
        attestations_dirs=list(attestations_dir) if attestations_dir else [],
    )
    report = collector.collect()
    payload = _EVIDENCE_ADAPTER.dump_python(report.evidence, mode="json")
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


@app.command("evaluate")
def cmd_evaluate(
    evidence_path: Annotated[
        Path, typer.Option("--evidence", help="Path to an evidence JSON list")
    ],
    application: Annotated[str, typer.Option(help="Application name")],
    repository: Annotated[str, typer.Option(help="Repository reference")],
    release_id: Annotated[str, typer.Option("--release-id")],
    commit_sha: Annotated[str, typer.Option("--commit-sha")],
    output_dir: Annotated[Path, typer.Option("--output-dir")] = Path("output"),
    branch: Annotated[str, typer.Option(help="Branch name")] = "main",
    environment: Annotated[str, typer.Option()] = "production",
    owner_team: Annotated[str | None, typer.Option()] = None,
    catalog_path: Annotated[Path | None, typer.Option("--catalog")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on")] = "not_ready",
) -> None:
    """Evaluate an existing evidence list and produce the full bundle outputs."""
    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence = _EVIDENCE_ADAPTER.validate_python(data)
    except (ValidationError, json.JSONDecodeError) as exc:
        console.print(f"[red]Invalid evidence file {evidence_path}:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    app_ = _build_application(application, repository, environment, owner_team)
    release = _build_release(release_id, commit_sha, branch, None, None, None, None)
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
    _render_summary(result)
    raise typer.Exit(code=_fail_on_exit_code(bundle.summary.release_status, fail_on))


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
    cmd_evaluate(
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


@app.command("controls")
def cmd_controls(
    catalog_path: Annotated[Path | None, typer.Option("--catalog")] = None,
) -> None:
    """Print the control catalog currently used for evaluation."""
    from evidence_collector.controls import default_catalog, load_catalog

    controls = load_catalog(catalog_path) if catalog_path else list(default_catalog())
    table = Table(title="Secure SDLC Control Catalog", show_lines=False)
    table.add_column("Control ID")
    table.add_column("Framework")
    table.add_column("Criticality")
    table.add_column("Required evidence")
    table.add_column("Recommended evidence")
    for control in controls:
        table.add_row(
            control.control_id,
            control.framework.value,
            control.criticality.value,
            ", ".join(t.value for t in control.required_evidence_types) or "-",
            ", ".join(t.value for t in control.recommended_evidence_types) or "-",
        )
    console.print(table)


@app.command("compare")
def cmd_compare(
    before: Annotated[Path, typer.Argument(help="Path to the baseline bundle.json")],
    after: Annotated[Path, typer.Argument(help="Path to the new bundle.json")],
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: table or json")
    ] = "table",
) -> None:
    """Compare two bundle.json files and summarize what changed."""
    try:
        baseline = load_bundle(before)
        candidate = load_bundle(after)
    except (ValidationError, json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Could not load bundles:[/red] {exc}")
        raise typer.Exit(code=3) from exc

    comparison = compare_bundles(baseline, candidate)
    if output_format.lower() == "json":
        console.print_json(data=comparison.to_dict())
        return

    table = Table(title=f"Bundle diff: {baseline.bundle_id} → {candidate.bundle_id}")
    table.add_column("Metric")
    table.add_column("Before")
    table.add_column("After")
    table.add_column("Delta")
    table.add_row(
        "release_status",
        comparison.before_release_status.value,
        comparison.after_release_status.value,
        "⬆" if comparison.after_release_status == ReleaseStatus.READY else "",
    )
    table.add_row(
        "coverage",
        str(baseline.summary.evidence_coverage_score),
        str(candidate.summary.evidence_coverage_score),
        f"{comparison.coverage_delta:+d}",
    )
    table.add_row(
        "confidence",
        str(baseline.summary.confidence_score),
        str(candidate.summary.confidence_score),
        f"{comparison.confidence_delta:+d}",
    )
    console.print(table)

    control_table = Table(title="Control-level diff")
    control_table.add_column("Control ID")
    control_table.add_column("Before")
    control_table.add_column("After")
    control_table.add_column("Change")
    for delta in comparison.control_deltas:
        control_table.add_row(
            delta.control_id,
            delta.before.value if delta.before else "-",
            delta.after.value if delta.after else "-",
            delta.category,
        )
    console.print(control_table)


@app.command("schema")
def cmd_schema(
    output_path: Annotated[
        Path | None,
        typer.Option("--output", help="Write JSON Schema to this file instead of stdout"),
    ] = None,
) -> None:
    """Emit the JSON Schema for EvidenceBundle so teams can validate externally."""
    schema = EvidenceBundle.model_json_schema()
    payload = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False)
    if output_path is None:
        typer.echo(payload)
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(payload + "\n", encoding="utf-8")
    console.print(f"[green]EvidenceBundle JSON Schema[/green] → {output_path}")


exceptions_app = typer.Typer(
    name="exceptions",
    help="Inspect and validate Secure SDLC exception (waiver) files.",
    no_args_is_help=True,
    add_completion=False,
)
app.add_typer(exceptions_app)


@exceptions_app.command("validate")
def cmd_exceptions_validate(
    path: Annotated[Path, typer.Argument(help="Exception YAML/JSON to validate")],
) -> None:
    """Validate an exception file against the canonical schema."""
    try:
        exception = parse_exception(path)
    except (ParseError, FileNotFoundError) as exc:
        console.print(f"[red]Invalid exception file:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(
        f"[green]{exception.exception_id}[/green] valid · control={exception.control_id} "
        f"· approver={exception.approver} · expires_at={exception.expires_at.isoformat()}"
    )


@exceptions_app.command("list")
def cmd_exceptions_list(
    directory: Annotated[
        Path, typer.Argument(help="Directory containing exception YAML/JSON files")
    ],
) -> None:
    """Walk a directory and list every valid exception."""
    if not directory.is_dir():
        console.print(f"[red]Not a directory:[/red] {directory}")
        raise typer.Exit(code=2)
    table = Table(title=f"Exceptions in {directory}")
    table.add_column("Exception ID")
    table.add_column("Control")
    table.add_column("Approver")
    table.add_column("Expires at")
    table.add_column("Scope")
    valid = 0
    invalid = 0
    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() not in {".yaml", ".yml", ".json"} or not path.is_file():
            continue
        try:
            exc = parse_exception(path)
        except (ParseError, FileNotFoundError) as err:
            invalid += 1
            console.print(f"[yellow]skipped[/yellow] {path}: {err}")
            continue
        valid += 1
        scope_bits: list[str] = []
        if exc.scope.application:
            scope_bits.append(f"app={exc.scope.application}")
        if exc.scope.release_id:
            scope_bits.append(f"release={exc.scope.release_id}")
        table.add_row(
            exc.exception_id,
            exc.control_id,
            exc.approver,
            exc.expires_at.isoformat(),
            ", ".join(scope_bits) or "global",
        )
    console.print(table)
    console.print(f"[bold]{valid}[/bold] valid · [yellow]{invalid}[/yellow] invalid")


def _fail_on_exit_code(status: ReleaseStatus, threshold: str) -> int:
    threshold_value = threshold.lower()
    rank = {"ready": 0, "conditional": 1, "not_ready": 2}
    if threshold_value not in rank:
        return _exit_code_for_status(status)
    status_rank = {
        ReleaseStatus.READY: 0,
        ReleaseStatus.CONDITIONAL: 1,
        ReleaseStatus.NOT_READY: 2,
    }[status]
    if status_rank >= rank[threshold_value]:
        return status_rank if status_rank > 0 else 0
    return 0


def _force_utf8_std_streams() -> None:
    # Windows terminals default to cp1252 and crash on Rich's Unicode
    # separators (→, ⬆). Reconfigure both streams to UTF-8 so the CLI
    # works out-of-the-box without requiring PYTHONIOENCODING=utf-8.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    """Console-script entrypoint."""
    _force_utf8_std_streams()
    # Print banner only when stdout is a TTY, to avoid polluting pipelines.
    if sys.stdout.isatty():
        console.print(
            f"[bold]Secure SDLC Evidence Collector[/bold] v{__version__} · "
            f"started at {datetime.now(tz=UTC).isoformat()}"
        )
    app()


if __name__ == "__main__":
    main()
