"""GitLab / GitLab CI collector.

Mirrors the GitHub adapter: reads MR (merge request) metadata and pipeline
run metadata from GitLab's REST API v4 and returns `NormalizedEvidence`
records via the shared normalization layer.

Security posture:
- credentials are read from the environment (`GITLAB_TOKEN` — personal or
  project access token) or passed explicitly; never logged,
- request URLs and response payloads are not logged at INFO level,
- bounded timeouts, single retry implicit via httpx default.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from evidence_collector.domain.models import NormalizedEvidence, ReleaseContext
from evidence_collector.normalizers import (
    normalize_pr_metadata,
    normalize_workflow_run,
)

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=15.0)
_DEFAULT_API = "https://gitlab.com/api/v4"


@dataclass
class GitLabCollectorConfig:
    """Configuration for the GitLab collector.

    `project` is either the numeric ID or the URL-encoded
    `group/subgroup/project` path. `token` may be None for public projects,
    but GitLab rate-limits anonymous traffic tightly — a token is strongly
    recommended in any CI context.
    """

    project: str
    api_base: str = _DEFAULT_API
    # Kept out of the generated `repr`. Nothing logs this config today, and a
    # test pins that, but the default `repr` put the bearer token one
    # `logger.debug("config=%s", config)` — or one traceback rendered with
    # locals — away from being written down somewhere it does not belong.
    token: str | None = field(default=None, repr=False)
    user_agent: str = "secure-sdlc-evidence-collector/2.5.1"  # x-release-please-version

    @classmethod
    def from_env(cls, project: str, api_base: str = _DEFAULT_API) -> GitLabCollectorConfig:
        return cls(
            project=project,
            api_base=api_base,
            token=os.getenv("GITLAB_TOKEN") or None,
        )


class GitLabCollector:
    """Collects MR and pipeline metadata from GitLab."""

    def __init__(
        self,
        config: GitLabCollectorConfig,
        release: ReleaseContext,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._config = config
        self._release = release
        self._owned_client = client is None
        self._client = client or httpx.Client(
            base_url=config.api_base,
            timeout=_DEFAULT_TIMEOUT,
            headers=self._default_headers(),
        )

    def _default_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": self._config.user_agent,
        }
        if self._config.token:
            headers["PRIVATE-TOKEN"] = self._config.token
        return headers

    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> GitLabCollector:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self._client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def collect_merge_request(self, mr_iid: int) -> NormalizedEvidence:
        """Collect a GitLab MR as `code_review` evidence."""
        project = self._config.project
        mr_payload: dict[str, Any] = self._get(f"/projects/{project}/merge_requests/{mr_iid}")
        approvals_payload: dict[str, Any] = self._get(
            f"/projects/{project}/merge_requests/{mr_iid}/approvals"
        )
        commits_payload: list[dict[str, Any]] = self._get(
            f"/projects/{project}/merge_requests/{mr_iid}/commits",
            params={"per_page": 100},
        )

        approvals_required = int(approvals_payload.get("approvals_required") or 1)
        approvals_left = int(approvals_payload.get("approvals_left") or 0)
        approvals_approved = max(0, approvals_required - approvals_left)

        approved_by_events = approvals_payload.get("approved_by") or []
        last_approval_at = _max_datetime(
            [
                entry.get("updated_at") or entry.get("created_at")
                for entry in approved_by_events
                if isinstance(entry, dict)
            ]
        )
        last_commit_at = _max_datetime(
            [c.get("committed_date") or c.get("authored_date") for c in commits_payload]
        )
        last_approval_after_last_commit = (
            last_commit_at is not None
            and last_approval_at is not None
            and last_approval_at >= last_commit_at
        )

        payload = {
            "number": mr_iid,
            "title": mr_payload.get("title"),
            "author": (mr_payload.get("author") or {}).get("username"),
            "html_url": mr_payload.get("web_url"),
            "merged": mr_payload.get("state") == "merged",
            "base": mr_payload.get("target_branch"),
            "head": mr_payload.get("source_branch"),
            "reviewers_required": approvals_required,
            "reviewers_approved": approvals_approved,
            "last_approval_after_last_commit": last_approval_after_last_commit,
            "collected_at": datetime.now(tz=UTC).isoformat(),
            "platform": "gitlab",
        }
        evidence = normalize_pr_metadata(payload, self._release)
        evidence.source.name = "gitlab"
        evidence.source.uri = mr_payload.get("web_url")
        evidence.producer = "gitlab-merge-request"
        return evidence

    def collect_pipeline(self, pipeline_id: int) -> NormalizedEvidence:
        """Collect a GitLab pipeline as `workflow_run` evidence."""
        project = self._config.project
        pipeline_payload: dict[str, Any] = self._get(f"/projects/{project}/pipelines/{pipeline_id}")
        # GitLab uses `status` (success, failed, canceled, skipped, …). We
        # map it to the `conclusion`-style field the normalizer expects.
        status = str(pipeline_payload.get("status") or "").lower()
        conclusion = {
            "success": "success",
            "failed": "failure",
            "canceled": "cancelled",
            "skipped": "cancelled",
            "running": "",
            "pending": "",
            "manual": "",
        }.get(status, status)
        payload = {
            "run_id": pipeline_id,
            "workflow_name": pipeline_payload.get("name") or "gitlab-pipeline",
            "conclusion": conclusion,
            "status": pipeline_payload.get("status"),
            "event": pipeline_payload.get("source"),
            "head_sha": pipeline_payload.get("sha"),
            "html_url": pipeline_payload.get("web_url"),
            "created_at": pipeline_payload.get("created_at"),
            "updated_at": pipeline_payload.get("updated_at"),
            "platform": "gitlab",
        }
        evidence = normalize_workflow_run(payload, self._release)
        evidence.source.name = "gitlab-ci"
        evidence.source.uri = pipeline_payload.get("web_url")
        evidence.producer = "gitlab-ci"
        return evidence


def _max_datetime(values: Sequence[str | None]) -> datetime | None:
    parsed: list[datetime] = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            parsed.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            continue
    if not parsed:
        return None
    return max(parsed)
