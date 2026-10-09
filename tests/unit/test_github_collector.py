"""Unit tests for the GitHub collector using httpx.MockTransport."""

from __future__ import annotations

import httpx
import pytest

from evidence_collector.collectors.github import GitHubCollector, GitHubCollectorConfig
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType


def _mock_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.unit
def test_collect_pull_request(sample_release) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/pulls/184"):
            return httpx.Response(
                200,
                json={
                    "number": 184,
                    "title": "Refactor refund service",
                    "user": {"login": "alice"},
                    "html_url": "https://github.com/acme/payments-api/pull/184",
                    "merged": True,
                    "base": {"ref": "main"},
                    "head": {"ref": "feature/refund", "sha": "c" * 40},
                    "requested_reviewers": [
                        {"login": "bob"},
                        {"login": "carol"},
                    ],
                },
            )
        if path.endswith("/pulls/184/reviews"):
            return httpx.Response(
                200,
                json=[
                    {
                        "user": {"login": "bob"},
                        "state": "APPROVED",
                        "commit_id": "c" * 40,
                        "submitted_at": "2026-04-10T12:30:00Z",
                    },
                    {
                        "user": {"login": "carol"},
                        "state": "APPROVED",
                        "commit_id": "c" * 40,
                        "submitted_at": "2026-04-10T12:45:00Z",
                    },
                ],
            )
        if path.endswith("/pulls/184/commits"):
            return httpx.Response(
                200,
                json=[
                    {
                        "commit": {
                            "committer": {"date": "2026-04-10T12:00:00Z"},
                        }
                    }
                ],
            )
        return httpx.Response(404, json={"message": "not found"})

    client = httpx.Client(
        base_url="https://api.github.com",
        transport=_mock_transport(handler),
    )
    try:
        collector = GitHubCollector(
            config=GitHubCollectorConfig(repository="acme/payments-api", token=None),
            release=sample_release,
            client=client,
        )
        evidence = collector.collect_pull_request(184)
    finally:
        client.close()

    assert evidence.evidence_type == EvidenceType.CODE_REVIEW
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata["reviewers_approved"] == 2
    assert evidence.metadata["last_approval_after_last_commit"] is True


@pytest.mark.unit
def test_collect_workflow_run(sample_release) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/actions/runs/1001"):
            return httpx.Response(
                200,
                json={
                    "name": "ci.yml",
                    "conclusion": "success",
                    "status": "completed",
                    "event": "push",
                    "head_sha": "abcdef1234567890",
                    "html_url": "https://github.com/acme/payments-api/actions/runs/1001",
                    "created_at": "2026-04-10T12:00:00Z",
                    "updated_at": "2026-04-10T12:05:00Z",
                },
            )
        return httpx.Response(404)

    client = httpx.Client(
        base_url="https://api.github.com",
        transport=_mock_transport(handler),
    )
    try:
        collector = GitHubCollector(
            config=GitHubCollectorConfig(repository="acme/payments-api"),
            release=sample_release,
            client=client,
        )
        evidence = collector.collect_workflow_run(1001)
    finally:
        client.close()

    assert evidence.evidence_type == EvidenceType.WORKFLOW_RUN
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata["workflow_name"] == "ci.yml"


# ---------------------------------------------------------------------------
# Approval staleness: the latest decisive review per reviewer counts, and an
# approval only counts when it was given on the PR head commit. Commit dates
# are author-controlled (GIT_COMMITTER_DATE), so they must not decide this.
# ---------------------------------------------------------------------------

_HEAD = "f" * 40
_OLD = "a" * 40
_API = "https://api.github.com"
_PR_PATH = "/repos/acme/payments-api/pulls/200"


def _review(login: str, state: str, commit_id: str, submitted_at: str) -> dict[str, object]:
    return {
        "user": {"login": login},
        "state": state,
        "commit_id": commit_id,
        "submitted_at": submitted_at,
    }


def _commit(date: str) -> dict[str, object]:
    return {"commit": {"committer": {"date": date}, "author": {"date": date}}}


def _pr_payload() -> dict[str, object]:
    return {
        "number": 200,
        "title": "Tighten refund limits",
        "user": {"login": "alice"},
        "html_url": "https://github.com/acme/payments-api/pull/200",
        "merged": False,
        "base": {"ref": "main", "sha": "b" * 40},
        "head": {"ref": "feature/limits", "sha": _HEAD},
        "requested_reviewers": [],
    }


def _paged(
    pages: list[list[dict[str, object]]], path: str, request: httpx.Request
) -> httpx.Response:
    page = int(request.url.params.get("page", "1"))
    headers = {}
    if page < len(pages):
        headers["Link"] = f'<{_API}{path}?per_page=100&page={page + 1}>; rel="next"'
    return httpx.Response(200, json=pages[page - 1], headers=headers)


def _collect(
    sample_release,
    reviews_pages: list[list[dict[str, object]]],
    commits_pages: list[list[dict[str, object]]] | None = None,
):
    commit_pages = commits_pages or [[_commit("2026-04-10T12:00:00Z")]]

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == _PR_PATH:
            return httpx.Response(200, json=_pr_payload())
        if path == f"{_PR_PATH}/reviews":
            return _paged(reviews_pages, path, request)
        if path == f"{_PR_PATH}/commits":
            return _paged(commit_pages, path, request)
        return httpx.Response(404, json={"message": "not found"})

    client = httpx.Client(base_url=_API, transport=_mock_transport(handler))
    try:
        collector = GitHubCollector(
            config=GitHubCollectorConfig(repository="acme/payments-api"),
            release=sample_release,
            client=client,
        )
        return collector.collect_pull_request(200)
    finally:
        client.close()


@pytest.mark.unit
def test_approval_then_changes_requested_does_not_pass(sample_release) -> None:
    evidence = _collect(
        sample_release,
        [
            [
                _review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z"),
                _review("bob", "CHANGES_REQUESTED", _HEAD, "2026-04-10T12:40:00Z"),
            ]
        ],
    )
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["reviewers_approved"] == 0
    assert evidence.metadata["changes_requested"] == 1


@pytest.mark.unit
def test_outstanding_change_request_blocks_other_approvals(sample_release) -> None:
    evidence = _collect(
        sample_release,
        [
            [
                _review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z"),
                _review("carol", "CHANGES_REQUESTED", _HEAD, "2026-04-10T12:40:00Z"),
            ]
        ],
    )
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["reviewers_approved"] == 1


@pytest.mark.unit
def test_comment_after_approval_keeps_the_approval(sample_release) -> None:
    evidence = _collect(
        sample_release,
        [
            [
                _review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z"),
                _review("bob", "COMMENTED", _HEAD, "2026-04-10T12:40:00Z"),
            ]
        ],
    )
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata["reviewers_approved"] == 1


@pytest.mark.unit
def test_dismissed_approval_does_not_count(sample_release) -> None:
    evidence = _collect(
        sample_release,
        [[_review("bob", "DISMISSED", _HEAD, "2026-04-10T12:30:00Z")]],
    )
    assert evidence.status != EvidenceStatus.PASSED
    assert evidence.metadata["reviewers_approved"] == 0


@pytest.mark.unit
def test_approval_on_older_commit_fails_even_with_backdated_head(sample_release) -> None:
    # The head commit claims a committer date before the approval, but the
    # approval was given on an older commit, so it says nothing about head.
    evidence = _collect(
        sample_release,
        [[_review("bob", "APPROVED", _OLD, "2026-04-10T12:30:00Z")]],
        [[_commit("2026-04-09T08:00:00Z")]],
    )
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["reviewers_approved"] == 0
    assert evidence.metadata["stale_approvals"] == 1
    assert evidence.metadata["last_approval_after_last_commit"] is False
    assert evidence.metadata["head_sha"] == _HEAD


@pytest.mark.unit
def test_valid_approval_on_head_passes(sample_release) -> None:
    evidence = _collect(
        sample_release,
        [[_review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z")]],
    )
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata["reviewers_approved"] == 1
    assert evidence.metadata["last_approval_after_last_commit"] is True


@pytest.mark.unit
def test_reviews_are_read_across_pages(sample_release) -> None:
    # 30 reviews on page one (the GitHub default page size) end with the
    # approval from bob; his change request lands on page two.
    first = [_review(f"user{i}", "COMMENTED", _HEAD, "2026-04-10T12:00:00Z") for i in range(29)] + [
        _review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z")
    ]
    second = [_review("bob", "CHANGES_REQUESTED", _HEAD, "2026-04-10T13:00:00Z")]
    evidence = _collect(sample_release, [first, second])
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["reviewers_approved"] == 0


@pytest.mark.unit
def test_approval_before_the_101st_commit_is_stale(sample_release) -> None:
    # The approval was given on commit 100; commit 101 (on page two of the
    # commit list) is the head. Reading only the first commit page made the
    # approval look fresh.
    commits_first = [_commit("2026-04-10T10:00:00Z") for _ in range(100)]
    commits_second = [_commit("2026-04-10T14:00:00Z")]
    evidence = _collect(
        sample_release,
        [[_review("bob", "APPROVED", _OLD, "2026-04-10T12:30:00Z")]],
        [commits_first, commits_second],
    )
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["reviewers_approved"] == 0


def _looping_collector(sample_release, next_link: str, token: str | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.github.com":
            return httpx.Response(200, json=[])
        if request.url.path == _PR_PATH:
            return httpx.Response(200, json=_pr_payload())
        return httpx.Response(
            200,
            json=[_review("bob", "APPROVED", _HEAD, "2026-04-10T12:30:00Z")],
            headers={"Link": f'<{next_link}>; rel="next"'},
        )

    client = httpx.Client(base_url=_API, transport=_mock_transport(handler))
    collector = GitHubCollector(
        config=GitHubCollectorConfig(repository="acme/payments-api", token=token),
        release=sample_release,
        client=client,
    )
    return client, collector


@pytest.mark.unit
def test_endless_review_pagination_fails_closed(sample_release) -> None:
    from evidence_collector.collectors._pagination import PaginationError

    client, collector = _looping_collector(sample_release, f"{_API}{_PR_PATH}/reviews?page=2")
    try:
        with pytest.raises(PaginationError):
            collector.collect_pull_request(200)
    finally:
        client.close()


@pytest.mark.unit
def test_next_link_to_another_host_is_refused(sample_release) -> None:
    from evidence_collector.collectors._pagination import PaginationError

    client, collector = _looping_collector(
        sample_release, "https://evil.example/steal?page=2", token="t"
    )
    try:
        with pytest.raises(PaginationError):
            collector.collect_pull_request(200)
    finally:
        client.close()
