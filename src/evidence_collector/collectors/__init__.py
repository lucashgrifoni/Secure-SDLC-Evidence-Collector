"""Collectors: ingestion adapters for local artifacts and external systems."""

from __future__ import annotations

from evidence_collector.collectors.github import GitHubCollector, GitHubCollectorConfig
from evidence_collector.collectors.gitlab import GitLabCollector, GitLabCollectorConfig
from evidence_collector.collectors.local import LocalArtifactCollector

__all__ = [
    "GitHubCollector",
    "GitHubCollectorConfig",
    "GitLabCollector",
    "GitLabCollectorConfig",
    "LocalArtifactCollector",
]
