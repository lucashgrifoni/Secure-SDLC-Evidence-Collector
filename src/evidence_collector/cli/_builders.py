"""Factories for the two domain inputs every command needs.

The CLI accepts free-form scalars and produces validated domain
objects. Keeping the factories in one place keeps Pydantic validation
errors consistent across commands.
"""

from __future__ import annotations

from evidence_collector.domain.models import Application, ReleaseContext


def build_application(
    name: str,
    repository: str,
    environment: str,
    owner_team: str | None,
) -> Application:
    """Build a validated :class:`Application` from CLI scalars."""
    return Application(
        name=name,
        repository=repository,
        environment=environment,
        owner_team=owner_team,
    )


def build_release(
    release_id: str,
    commit_sha: str,
    branch: str,
    pipeline_run_id: str | None = None,
    build_id: str | None = None,
    artifact_digest: str | None = None,
    tag: str | None = None,
) -> ReleaseContext:
    """Build a validated :class:`ReleaseContext` from CLI scalars."""
    return ReleaseContext(
        release_id=release_id,
        commit_sha=commit_sha,
        branch=branch,
        pipeline_run_id=pipeline_run_id,
        build_id=build_id,
        artifact_digest=artifact_digest,
        tag=tag,
    )
