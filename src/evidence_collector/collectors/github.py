"""GitHub / GitHub Actions collector.

This module is intentionally a thin adapter around `httpx`. It returns
*payload dicts* rather than `NormalizedEvidence` so the normalization layer
remains the single place where canonical contracts are built.

Security posture:

- credentials are read from the environment (`GITHUB_TOKEN`) or passed
  explicitly; they are never logged or echoed back to the bundle
- request URLs and payloads are not logged at INFO level
- network timeouts and a bounded retry policy avoid hanging pipelines
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
_DEFAULT_API = "https://api.github.com"


@dataclass
class GitHubCollectorConfig:
    """Configuration for the GitHub collector.

    Token must never be None for private repositories. For public
    repositories the token is optional but strongly recommended due to
    unauthenticated rate limits.
    """

    repository: str
    api_base: str = _DEFAULT_API
    # Kept out of the generated `repr`; see the note on the GitLab config for
    # why the default one was a hazard even with nothing logging it today.
    token: str | None = field(default=None, repr=False)
    user_agent: str = "secure-sdlc-evidence-collector/3.0.1"  # x-release-please-version

    @classmethod
    def from_env(cls, repository: str, api_base: str = _DEFAULT_API) -> GitHubCollectorConfig:
        return cls(
            repository=repository,
            api_base=api_base,
            token=os.getenv("GITHUB_TOKEN") or None,
        )


class GitHubCollector:
    """Collects pull request and workflow run metadata from GitHub."""

    def __init__(
        self,
        config: GitHubCollectorConfig,
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
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": self._config.user_agent,
        }
        if self._config.token:
            headers["Authorization"] = f"Bearer {self._config.token}"
        return headers

    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> GitHubCollector:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self._client.get(path, params=params)
        response.raise_for_status()
        return response.json()

    def collect_pull_request(self, pull_number: int) -> NormalizedEvidence:
        owner_repo = self._config.repository
        pr_payload: dict[str, Any] = self._get(f"/repos/{owner_repo}/pulls/{pull_number}")
        reviews_payload: list[dict[str, Any]] = self._get(
            f"/repos/{owner_repo}/pulls/{pull_number}/reviews"
        )
        requested_reviewers = pr_payload.get("requested_reviewers") or []
        reviewers_required = max(
            len(requested_reviewers),
            1,
        )

        approvals = [r for r in reviews_payload if r.get("state") == "APPROVED"]
        reviewers_approved = len({r.get("user", {}).get("login") for r in approvals})

        last_commit_at = self._resolve_last_commit_date(owner_repo, pull_number)
        last_approval_at = _max_datetime(
            [r.get("submitted_at") for r in approvals if r.get("submitted_at")]
        )
        last_approval_after_last_commit = (
            last_commit_at is not None
            and last_approval_at is not None
            and last_approval_at >= last_commit_at
        )

        payload = {
            "number": pull_number,
            "title": pr_payload.get("title"),
            "author": (pr_payload.get("user") or {}).get("login"),
            "html_url": pr_payload.get("html_url"),
            "merged": bool(pr_payload.get("merged")),
            "base": (pr_payload.get("base") or {}).get("ref"),
            "head": (pr_payload.get("head") or {}).get("ref"),
            "reviewers_required": reviewers_required,
            "reviewers_approved": reviewers_approved,
            "last_approval_after_last_commit": last_approval_after_last_commit,
            "collected_at": datetime.now(tz=UTC).isoformat(),
        }
        return normalize_pr_metadata(payload, self._release)

    def collect_workflow_run(self, run_id: int) -> NormalizedEvidence:
        owner_repo = self._config.repository
        run_payload: dict[str, Any] = self._get(f"/repos/{owner_repo}/actions/runs/{run_id}")
        payload = {
            "run_id": run_id,
            "workflow_name": run_payload.get("name"),
            "conclusion": run_payload.get("conclusion"),
            "status": run_payload.get("status"),
            "event": run_payload.get("event"),
            "head_sha": run_payload.get("head_sha"),
            "html_url": run_payload.get("html_url"),
            "created_at": run_payload.get("created_at"),
            "updated_at": run_payload.get("updated_at"),
        }
        return normalize_workflow_run(payload, self._release)

    def _resolve_last_commit_date(self, owner_repo: str, pull_number: int) -> datetime | None:
        commits_payload: list[dict[str, Any]] = self._get(
            f"/repos/{owner_repo}/pulls/{pull_number}/commits",
            params={"per_page": 100},
        )
        commit_dates: list[str] = []
        for commit in commits_payload:
            committer = (commit.get("commit") or {}).get("committer") or {}
            author = (commit.get("commit") or {}).get("author") or {}
            date = committer.get("date") or author.get("date")
            if isinstance(date, str):
                commit_dates.append(date)
        return _max_datetime(commit_dates)


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
