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
                    "head": {"ref": "feature/refund"},
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
                        "submitted_at": "2026-04-10T12:30:00Z",
                    },
                    {
                        "user": {"login": "carol"},
                        "state": "APPROVED",
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
