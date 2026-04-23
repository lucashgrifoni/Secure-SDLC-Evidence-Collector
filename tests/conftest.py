"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
)


@pytest.fixture
def sample_commit_sha() -> str:
    return "abc123def4567890"


@pytest.fixture
def sample_release(sample_commit_sha: str) -> ReleaseContext:
    return ReleaseContext(
        release_id="2026.04.10",
        commit_sha=sample_commit_sha,
        branch="main",
        pipeline_run_id="gha-93821",
        build_id="build-2041",
        artifact_digest="sha256:0123456789abcdef0123456789abcdef",
        tag="v2026.04.10",
    )


@pytest.fixture
def sample_application() -> Application:
    return Application(
        name="payments-api",
        repository="acme/payments-api",
        environment="production",
        owner_team="payments-core",
    )


@pytest.fixture
def sample_evidence_source() -> EvidenceSource:
    return EvidenceSource(name="semgrep", kind="sarif", version="1.70.0")


@pytest.fixture
def sample_evidence(
    sample_release: ReleaseContext, sample_evidence_source: EvidenceSource
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id="ev-001",
        evidence_type=EvidenceType.SAST_SCAN,
        source=sample_evidence_source,
        producer="semgrep",
        subject_type=SubjectType.COMMIT,
        subject_ref=sample_release.commit_sha,
        status=EvidenceStatus.PASSED,
        confidence=ConfidenceLevel.HIGH,
        release_id=sample_release.release_id,
        commit_sha=sample_release.commit_sha,
        summary="No high/critical findings",
    )


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


@pytest.fixture
def sample_release_root() -> Path:
    return Path(__file__).resolve().parent.parent / "examples" / "sample_release"
