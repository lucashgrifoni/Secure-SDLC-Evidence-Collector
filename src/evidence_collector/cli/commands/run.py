"""``sdlc-evidence run`` — full pipeline: collect, evaluate, export."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.application.profiles import ReleaseProfile
from evidence_collector.cli._builders import build_application, build_release
from evidence_collector.cli._exit_codes import fail_on_exit_code
from evidence_collector.cli._render import render_collection_errors, render_summary
from evidence_collector.collectors.github import GitHubCollector, GitHubCollectorConfig
from evidence_collector.domain.models import NormalizedEvidence
from evidence_collector.scoring import (
    DEFAULT_EPSS_PERCENTILE_THRESHOLD,
    RiskMode,
    RiskThresholds,
)


def register(app: typer.Typer) -> None:
    """Attach the ``run`` command to ``app``."""

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
            typer.Option(
                "--pull-request",
                help="GitHub PR number to pull code-review evidence from",
            ),
        ] = None,
        workflow_run: Annotated[
            int | None,
            typer.Option("--workflow-run", help="GitHub Actions run ID to record"),
        ] = None,
        fail_on: Annotated[
            str,
            typer.Option(
                "--fail-on",
                help=(
                    "Exit non-zero when release_status reaches this severity: "
                    "ready|conditional|not_ready"
                ),
            ),
        ] = "not_ready",
        artifact_root: Annotated[
            Path | None,
            typer.Option(
                "--artifact-root",
                help=(
                    "Base directory that absolute artifact paths are rewritten against. "
                    "Set this (e.g. to the repository root) so the bundle records "
                    "repo-relative paths instead of leaking local filesystem "
                    "locations."
                ),
            ),
        ] = None,
        risk_mode: Annotated[
            str,
            typer.Option(
                "--risk-mode",
                help=(
                    "Verdict mode: 'off' (default; presence-based) or "
                    "'epss-weighted' (re-derive release_status from EPSS + KEV "
                    "data already in the bundle). Off preserves byte-stability."
                ),
            ),
        ] = "off",
        epss_percentile_threshold: Annotated[
            float,
            typer.Option(
                "--epss-percentile-threshold",
                help=(
                    "Under --risk-mode epss-weighted, a CVE with EPSS percentile "
                    ">= this value is treated as exploitable. Default 0.70."
                ),
                min=0.0,
                max=1.0,
            ),
        ] = DEFAULT_EPSS_PERCENTILE_THRESHOLD,
        profile: Annotated[
            str,
            typer.Option(
                "--profile",
                help=(
                    "Regulatory profile: 'none' (default), 'cra-2026' (EU CRA "
                    "24h disclosure annotations), or 'fedramp-20x' (FedRAMP 20x "
                    "retention metadata). Annotates evidence; does not change "
                    "the verdict."
                ),
            ),
        ] = "none",
    ) -> None:
        """Run the full pipeline: collect, evaluate, and export the bundle."""
        if risk_mode not in {"off", "epss-weighted"}:
            raise typer.BadParameter(
                f"--risk-mode must be 'off' or 'epss-weighted'; got '{risk_mode}'."
            )
        if profile not in {p.value for p in ReleaseProfile}:
            raise typer.BadParameter(
                f"--profile must be one of {sorted(p.value for p in ReleaseProfile)}; "
                f"got '{profile}'."
            )
        app_ = build_application(application, repository, environment, owner_team)
        release = build_release(
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
            artifact_root=artifact_root,
            risk_mode=RiskMode(risk_mode),
            risk_thresholds=RiskThresholds(epss_percentile_threshold=epss_percentile_threshold),
            profile=ReleaseProfile(profile),
        )
        render_summary(result)
        render_collection_errors(result)

        raise typer.Exit(code=fail_on_exit_code(result.bundle.summary.release_status, fail_on))
