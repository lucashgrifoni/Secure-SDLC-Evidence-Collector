"""Unit tests for the scoring engine."""

from __future__ import annotations

from evidence_collector.controls import default_catalog, evaluate_controls
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceSource,
    NormalizedEvidence,
)
from evidence_collector.scoring import build_summary, compute_release_status


def _ev(
    evidence_type: EvidenceType,
    status: EvidenceStatus = EvidenceStatus.PASSED,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=f"ev-{evidence_type.value}",
        evidence_type=evidence_type,
        source=EvidenceSource(name="t", kind="t"),
        producer="t",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567",
        status=status,
        confidence=confidence,
        release_id="r",
        commit_sha="abcdef1234567",
    )


def test_release_ready_with_full_evidence_set() -> None:
    catalog = default_catalog()
    evidence = [
        _ev(EvidenceType.SAST_SCAN),
        _ev(EvidenceType.SCA_SCAN),
        _ev(EvidenceType.SECRETS_SCAN),
        _ev(EvidenceType.SBOM, status=EvidenceStatus.GENERATED),
        _ev(EvidenceType.TEST_RESULT),
        _ev(EvidenceType.CODE_REVIEW),
        _ev(EvidenceType.PR_METADATA),
        _ev(EvidenceType.THREAT_MODEL),
        _ev(EvidenceType.RELEASE_APPROVAL),
        _ev(EvidenceType.ROLLBACK_PLAN),
        _ev(EvidenceType.ARTIFACT_SIGNATURE),
        _ev(EvidenceType.ARTIFACT_ATTESTATION),
    ]
    evaluations, gaps = evaluate_controls(catalog, evidence)
    summary = build_summary(catalog, evaluations, gaps)
    assert summary.release_status == ReleaseStatus.READY
    assert summary.evidence_coverage_score == 100
    assert summary.confidence_score == 100
    assert not summary.missing_critical_evidence


def test_release_not_ready_when_critical_missing() -> None:
    catalog = default_catalog()
    evidence = [
        _ev(EvidenceType.SAST_SCAN),
        _ev(EvidenceType.SCA_SCAN),
    ]
    evaluations, gaps = evaluate_controls(catalog, evidence)
    summary = build_summary(catalog, evaluations, gaps)
    assert summary.release_status == ReleaseStatus.NOT_READY
    assert summary.missing_critical_evidence


def test_release_conditional_when_only_medium_gap() -> None:
    catalog = default_catalog()
    evidence = [
        _ev(EvidenceType.SAST_SCAN),
        _ev(EvidenceType.SCA_SCAN),
        _ev(EvidenceType.SECRETS_SCAN),
        _ev(EvidenceType.SBOM, status=EvidenceStatus.GENERATED),
        _ev(EvidenceType.TEST_RESULT),
        _ev(EvidenceType.CODE_REVIEW),
        _ev(EvidenceType.PR_METADATA),
        _ev(EvidenceType.RELEASE_APPROVAL),
        _ev(EvidenceType.ROLLBACK_PLAN),
        _ev(EvidenceType.ARTIFACT_SIGNATURE),
        _ev(EvidenceType.ARTIFACT_ATTESTATION),
    ]  # note: missing threat_model (medium control)
    evaluations, gaps = evaluate_controls(catalog, evidence)
    summary = build_summary(catalog, evaluations, gaps)
    assert summary.release_status == ReleaseStatus.CONDITIONAL
    assert summary.evidence_coverage_score < 100


def test_compute_release_status_with_no_gaps() -> None:
    assert compute_release_status([], []) == ReleaseStatus.READY
