"""Behaviour tests for `collectors/gitlab.py` against a mocked GitLab API.

Mirrors the GitHub collector test pattern (`test_github_collector.py`)
so the two adapters share the same evidence shape contract.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from evidence_collector.collectors.gitlab import (
    GitLabCollector,
    GitLabCollectorConfig,
    _max_datetime,
)
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import NormalizedEvidence


def _client(handler) -> httpx.Client:
    return httpx.Client(
        base_url="https://gitlab.com/api/v4",
        transport=httpx.MockTransport(handler),
    )


# ---------------------------------------------------------------------------
# Configuration & headers — token never leaks, token absent works.
# ---------------------------------------------------------------------------


def test_config_from_env_picks_up_gitlab_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test-token")
    cfg = GitLabCollectorConfig.from_env(project="my/group/repo")
    assert cfg.project == "my/group/repo"
    assert cfg.token == "glpat-test-token"


def test_config_from_env_handles_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    cfg = GitLabCollectorConfig.from_env(project="public/repo")
    assert cfg.token is None


def test_default_headers_include_token_only_when_set(sample_release) -> None:
    with_token = GitLabCollector(
        GitLabCollectorConfig(project="o/p", token="glpat-secret"),
        sample_release,
    )
    without_token = GitLabCollector(
        GitLabCollectorConfig(project="o/p", token=None),
        sample_release,
    )
    try:
        h_with = with_token._default_headers()
        h_without = without_token._default_headers()
    finally:
        with_token.close()
        without_token.close()
    assert h_with["PRIVATE-TOKEN"] == "glpat-secret"
    assert "PRIVATE-TOKEN" not in h_without
    # User-Agent and Accept must always be set.
    assert h_with["User-Agent"].startswith("secure-sdlc-evidence-collector/")
    assert h_with["Accept"] == "application/json"


# ---------------------------------------------------------------------------
# collect_merge_request — happy path with one approver, last approval after
# last commit.
# ---------------------------------------------------------------------------


def test_collect_merge_request_marks_approval_after_last_commit(
    sample_release,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if (
            path.endswith("/merge_requests/12")
            and "approvals" not in path
            and "commits" not in path
        ):
            return httpx.Response(
                200,
                json={
                    "iid": 12,
                    "title": "Migrate billing service",
                    "author": {"username": "alice"},
                    "web_url": "https://gitlab.com/o/p/-/merge_requests/12",
                    "state": "merged",
                    "target_branch": "main",
                    "source_branch": "feature/billing",
                    "sha": "c" * 40,
                },
            )
        if path.endswith("/merge_requests/12/approvals"):
            return httpx.Response(
                200,
                json={
                    "approvals_required": 2,
                    "approvals_left": 0,
                    "approved_by": [
                        {
                            "user": {"username": "bob"},
                            "updated_at": "2026-04-10T12:30:00Z",
                        },
                        {
                            "user": {"username": "carol"},
                            "updated_at": "2026-04-10T12:45:00Z",
                        },
                    ],
                },
            )
        if path.endswith("/merge_requests/12/versions"):
            return httpx.Response(
                200,
                json=[{"head_commit_sha": "c" * 40, "created_at": "2026-04-10T12:05:00Z"}],
            )
        if path.endswith("/merge_requests/12/commits"):
            return httpx.Response(
                200,
                json=[
                    {"committed_date": "2026-04-10T12:00:00Z"},
                    {"authored_date": "2026-04-10T11:30:00Z"},
                ],
            )
        return httpx.Response(404, json={"message": "not found"})

    client = _client(handler)
    try:
        collector = GitLabCollector(
            GitLabCollectorConfig(project="o/p"),
            sample_release,
            client=client,
        )
        evidence = collector.collect_merge_request(12)
    finally:
        client.close()

    assert evidence.evidence_type is EvidenceType.CODE_REVIEW
    assert evidence.status is EvidenceStatus.PASSED
    assert evidence.metadata["reviewers_required"] == 2
    assert evidence.metadata["reviewers_approved"] == 2
    assert evidence.metadata["last_approval_after_last_commit"] is True
    # Identity normalization done by the collector
    assert evidence.source.name == "gitlab"
    assert evidence.producer == "gitlab-merge-request"


def test_collect_merge_request_flags_unapproved_after_last_commit(
    sample_release,
) -> None:
    """An MR where the last commit lands AFTER the last approval must surface
    `last_approval_after_last_commit: False` so downstream evaluation can
    distinguish stale approvals."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/merge_requests/9") and "approvals" not in path and "commits" not in path:
            return httpx.Response(
                200,
                json={
                    "iid": 9,
                    "title": "Refactor",
                    "author": {"username": "alice"},
                    "web_url": "https://gitlab.com/o/p/-/merge_requests/9",
                    "state": "opened",
                    "target_branch": "main",
                    "source_branch": "x",
                    "sha": "d" * 40,
                },
            )
        if path.endswith("/merge_requests/9/approvals"):
            return httpx.Response(
                200,
                json={
                    "approvals_required": 1,
                    "approvals_left": 0,
                    "approved_by": [
                        {
                            "user": {"username": "bob"},
                            "updated_at": "2026-04-10T11:00:00Z",
                        },
                    ],
                },
            )
        if path.endswith("/merge_requests/9/versions"):
            return httpx.Response(
                200,
                json=[{"head_commit_sha": "d" * 40, "created_at": "2026-04-10T15:00:00Z"}],
            )
        if path.endswith("/merge_requests/9/commits"):
            return httpx.Response(
                200,
                json=[{"committed_date": "2026-04-10T15:00:00Z"}],
            )
        return httpx.Response(404)

    client = _client(handler)
    try:
        collector = GitLabCollector(
            GitLabCollectorConfig(project="o/p"),
            sample_release,
            client=client,
        )
        evidence = collector.collect_merge_request(9)
    finally:
        client.close()

    assert evidence.metadata["last_approval_after_last_commit"] is False
    # Approval count still reports correctly.
    assert evidence.metadata["reviewers_approved"] == 1
    # A stale approval must not let the code review pass.
    assert evidence.status is EvidenceStatus.FAILED


# ---------------------------------------------------------------------------
# Head-version binding: GitLab does not tie an approval to a commit, so the
# collector compares the approval time with the time GitLab itself recorded
# the head commit (MR diff versions), never with author-controlled commit
# dates, and reads every page of versions.
# ---------------------------------------------------------------------------

_GL_API = "https://gitlab.com/api/v4"
_GL_HEAD = "e" * 40


def _gl_paged(pages: list[list[Any]], path: str, request: httpx.Request) -> httpx.Response:
    page = int(request.url.params.get("page", "1"))
    headers = {}
    if page < len(pages):
        headers["Link"] = f'<{_GL_API}{path}?per_page=100&page={page + 1}>; rel="next"'
    return httpx.Response(200, json=pages[page - 1], headers=headers)


def _collect_mr(
    sample_release: Any,
    approved_by: list[dict[str, Any]],
    versions_pages: list[list[Any]],
    commits_pages: list[list[Any]],
) -> NormalizedEvidence:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/merge_requests/30"):
            return httpx.Response(
                200,
                json={
                    "iid": 30,
                    "title": "Raise limits",
                    "author": {"username": "alice"},
                    "web_url": "https://gitlab.com/o/p/-/merge_requests/30",
                    "state": "opened",
                    "target_branch": "main",
                    "source_branch": "limits",
                    "sha": _GL_HEAD,
                },
            )
        if path.endswith("/merge_requests/30/approvals"):
            return httpx.Response(
                200,
                json={"approvals_required": 1, "approvals_left": 0, "approved_by": approved_by},
            )
        if path.endswith("/merge_requests/30/versions"):
            return _gl_paged(versions_pages, path, request)
        if path.endswith("/merge_requests/30/commits"):
            return _gl_paged(commits_pages, path, request)
        return httpx.Response(404)

    client = _client(handler)
    try:
        collector = GitLabCollector(
            GitLabCollectorConfig(project="o/p"), sample_release, client=client
        )
        return collector.collect_merge_request(30)
    finally:
        client.close()


def test_backdated_head_commit_does_not_refresh_an_old_approval(sample_release) -> None:
    # The head commit claims a date before the approval, but GitLab recorded
    # the push of that head after the approval was given.
    evidence = _collect_mr(
        sample_release,
        [{"user": {"username": "bob"}, "updated_at": "2026-04-10T12:00:00Z"}],
        [[{"head_commit_sha": _GL_HEAD, "created_at": "2026-04-10T15:00:00Z"}]],
        [[{"committed_date": "2026-04-09T08:00:00Z"}]],
    )
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.metadata["last_approval_after_last_commit"] is False
    assert evidence.metadata["head_sha"] == _GL_HEAD


def test_head_version_on_a_later_page_is_found(sample_release) -> None:
    older = [
        {"head_commit_sha": f"{i:040x}", "created_at": "2026-04-10T10:00:00Z"} for i in range(100)
    ]
    newest = [{"head_commit_sha": _GL_HEAD, "created_at": "2026-04-10T15:00:00Z"}]
    evidence = _collect_mr(
        sample_release,
        [{"user": {"username": "bob"}, "updated_at": "2026-04-10T12:00:00Z"}],
        [older, newest],
        [
            [{"committed_date": "2026-04-10T10:00:00Z"} for _ in range(100)],
            [{"committed_date": "2026-04-10T15:00:00Z"}],
        ],
    )
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.metadata["last_approval_after_last_commit"] is False


def test_approval_after_head_version_passes(sample_release) -> None:
    evidence = _collect_mr(
        sample_release,
        [{"user": {"username": "bob"}, "updated_at": "2026-04-10T16:00:00Z"}],
        [[{"head_commit_sha": _GL_HEAD, "created_at": "2026-04-10T15:00:00Z"}]],
        [[{"committed_date": "2026-04-10T15:00:00Z"}]],
    )
    assert evidence.status is EvidenceStatus.PASSED
    assert evidence.metadata["last_approval_after_last_commit"] is True


def test_approval_without_timestamp_fails_closed(sample_release) -> None:
    evidence = _collect_mr(
        sample_release,
        [{"user": {"username": "bob"}}],
        [[{"head_commit_sha": _GL_HEAD, "created_at": "2026-04-10T15:00:00Z"}]],
        [[{"committed_date": "2026-04-10T15:00:00Z"}]],
    )
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.metadata["last_approval_after_last_commit"] is False


def test_missing_head_version_fails_closed(sample_release) -> None:
    evidence = _collect_mr(
        sample_release,
        [{"user": {"username": "bob"}, "updated_at": "2026-04-10T16:00:00Z"}],
        [[{"head_commit_sha": "0" * 40, "created_at": "2026-04-10T15:00:00Z"}]],
        [[{"committed_date": "2026-04-10T15:00:00Z"}]],
    )
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.metadata["last_approval_after_last_commit"] is False


# ---------------------------------------------------------------------------
# collect_pipeline — status mapping table (success / failed / canceled /
# skipped / running) is the public contract.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gitlab_status", "expected_evidence_status"),
    [
        ("success", EvidenceStatus.PASSED),
        ("failed", EvidenceStatus.FAILED),
        # GitLab `canceled` and `skipped` are translated to `cancelled` by
        # the GitLab adapter, which the workflow normalizer treats as
        # FAILED (same bucket as GitHub Actions `cancelled`).
        ("canceled", EvidenceStatus.FAILED),
        ("skipped", EvidenceStatus.FAILED),
        # `running` / `pending` / `manual` map to "" (in-progress) — the
        # normalizer falls through to COMPLETED.
        ("running", EvidenceStatus.COMPLETED),
        ("pending", EvidenceStatus.COMPLETED),
    ],
)
def test_collect_pipeline_maps_gitlab_status_to_evidence_status(
    sample_release,
    gitlab_status: str,
    expected_evidence_status: EvidenceStatus,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/pipelines/4242"):
            return httpx.Response(
                200,
                json={
                    "id": 4242,
                    "status": gitlab_status,
                    "source": "push",
                    "sha": "abcdef1234567890",
                    "web_url": "https://gitlab.com/o/p/-/pipelines/4242",
                    "name": "deploy",
                    "created_at": "2026-04-10T12:00:00Z",
                    "updated_at": "2026-04-10T12:30:00Z",
                },
            )
        return httpx.Response(404)

    client = _client(handler)
    try:
        collector = GitLabCollector(
            GitLabCollectorConfig(project="o/p"),
            sample_release,
            client=client,
        )
        evidence = collector.collect_pipeline(4242)
    finally:
        client.close()

    assert evidence.evidence_type is EvidenceType.WORKFLOW_RUN
    assert evidence.status is expected_evidence_status
    assert evidence.metadata["workflow_name"] == "deploy"
    assert evidence.source.name == "gitlab-ci"
    assert evidence.producer == "gitlab-ci"


# ---------------------------------------------------------------------------
# _max_datetime helper — also covered indirectly via the MR tests above.
# ---------------------------------------------------------------------------


def test_max_datetime_returns_max_when_inputs_valid() -> None:
    result = _max_datetime(["2026-04-10T12:00:00Z", "2026-04-10T13:00:00Z", None])
    assert result is not None
    assert result.isoformat() == "2026-04-10T13:00:00+00:00"


def test_max_datetime_skips_unparseable_strings() -> None:
    result = _max_datetime(["not-a-date", None, "2026-04-10T12:00:00Z"])
    assert result is not None
    assert result.isoformat() == "2026-04-10T12:00:00+00:00"


def test_max_datetime_returns_none_when_no_valid_inputs() -> None:
    assert _max_datetime([None, "garbage"]) is None
    assert _max_datetime([]) is None


# ---------------------------------------------------------------------------
# Context manager protocol.
# ---------------------------------------------------------------------------


def test_collector_supports_context_manager(sample_release) -> None:
    cfg = GitLabCollectorConfig(project="o/p")
    with GitLabCollector(cfg, sample_release) as collector:
        assert collector._owned_client is True
    # After exit the owned client is closed; calling close() again is a no-op
    # (httpx.Client.close is idempotent).
