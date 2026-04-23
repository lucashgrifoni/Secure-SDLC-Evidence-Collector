"""Unit tests for domain models and bundle schema."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
    Summary,
)


def test_commit_sha_normalization() -> None:
    release = ReleaseContext(release_id="r1", commit_sha="AbCdEf1234567890")
    assert release.commit_sha == "abcdef1234567890"


def test_commit_sha_rejects_non_hex() -> None:
    with pytest.raises(ValidationError):
        ReleaseContext(release_id="r1", commit_sha="zzz12345")


def test_manual_flag_downgrades_high_confidence() -> None:
    release = ReleaseContext(release_id="r1", commit_sha="abcdef1234567")
    evidence = NormalizedEvidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.RELEASE_APPROVAL,
        source=EvidenceSource(name="manual", kind="attestation"),
        producer="cab",
        subject_type=SubjectType.RELEASE,
        subject_ref="r1",
        status=EvidenceStatus.PASSED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        manual=True,
    )
    assert evidence.confidence == ConfidenceLevel.MEDIUM


def test_raw_evidence_ref_requires_locator() -> None:
    with pytest.raises(ValidationError):
        RawEvidenceRef()


def test_bundle_round_trip(sample_application: Application, sample_release: ReleaseContext) -> None:
    evidence = NormalizedEvidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name="cyclonedx", kind="sbom"),
        producer="cyclonedx",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="payments-api:2026.04.10",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=sample_release.release_id,
        commit_sha=sample_release.commit_sha,
    )
    evaluation = ControlEvaluation(
        control_id="SSDF-PS.3",
        framework=ControlFramework.NIST_SSDF,
        control_name="Archive and protect each software release",
        evaluation_status=ControlEvaluationStatus.MET,
        criticality=ControlCriticality.CRITICAL,
        evidence_refs=["ev-1"],
        confidence=ConfidenceLevel.HIGH,
        rationale="SBOM present and associated with release",
    )
    summary = Summary(
        evidence_coverage_score=100,
        confidence_score=100,
        release_status=ReleaseStatus.READY,
        total_controls=1,
        controls_met=1,
        controls_partial=0,
        controls_missing=0,
        controls_waived=0,
        controls_not_applicable=0,
    )
    bundle = EvidenceBundle(
        bundle_id="bundle-test",
        application=sample_application,
        release=sample_release,
        evidence=[evidence],
        control_evaluations=[evaluation],
        summary=summary,
    )
    payload = bundle.model_dump(mode="json")
    rehydrated = EvidenceBundle.model_validate(payload)
    assert rehydrated.summary.release_status == ReleaseStatus.READY
    assert rehydrated.evidence[0].evidence_id == "ev-1"


def test_bundle_rejects_dangling_evidence_refs(
    sample_application: Application, sample_release: ReleaseContext
) -> None:
    summary = Summary(
        evidence_coverage_score=0,
        confidence_score=0,
        release_status=ReleaseStatus.NOT_READY,
        total_controls=1,
        controls_met=0,
        controls_partial=0,
        controls_missing=1,
        controls_waived=0,
        controls_not_applicable=0,
    )
    evaluation = ControlEvaluation(
        control_id="SSDF-PS.3",
        framework=ControlFramework.NIST_SSDF,
        control_name="Archive and protect each software release",
        evaluation_status=ControlEvaluationStatus.MISSING,
        criticality=ControlCriticality.CRITICAL,
        evidence_refs=["does-not-exist"],
        confidence=ConfidenceLevel.LOW,
        rationale="missing",
    )
    with pytest.raises(ValidationError):
        EvidenceBundle(
            bundle_id="bundle-x",
            application=sample_application,
            release=sample_release,
            evidence=[],
            control_evaluations=[evaluation],
            summary=summary,
        )


def test_summary_counters_must_be_consistent() -> None:
    with pytest.raises(ValidationError):
        Summary(
            evidence_coverage_score=10,
            confidence_score=10,
            release_status=ReleaseStatus.NOT_READY,
            total_controls=5,
            controls_met=1,
            controls_partial=0,
            controls_missing=1,
            controls_waived=0,
            controls_not_applicable=0,
        )


def test_control_definition_requires_some_evidence_type() -> None:
    with pytest.raises(ValidationError):
        ControlDefinition(
            control_id="X",
            framework=ControlFramework.ORG_INTERNAL,
            name="X",
            description="missing evidence type",
            criticality=ControlCriticality.LOW,
        )
