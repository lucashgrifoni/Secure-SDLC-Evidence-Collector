"""Unit tests for the controls engine."""

from __future__ import annotations

from evidence_collector.controls import default_catalog, evaluate_controls
from evidence_collector.controls.engine import evaluate_control
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    ControlDefinition,
    EvidenceSource,
    NormalizedEvidence,
)


def _evidence(
    evidence_type: EvidenceType,
    status: EvidenceStatus = EvidenceStatus.PASSED,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    manual: bool = False,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=f"ev-{evidence_type.value}",
        evidence_type=evidence_type,
        source=EvidenceSource(name="test", kind="test"),
        producer="test",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567",
        status=status,
        confidence=confidence,
        release_id="r1",
        commit_sha="abcdef1234567",
        manual=manual,
    )


def test_default_catalog_loads_and_is_non_empty() -> None:
    catalog = default_catalog()
    assert len(catalog) >= 10
    ids = {c.control_id for c in catalog}
    assert "SSDF-PS.3" in ids
    assert "ORG-CODE-REVIEW" in ids


def test_control_met_when_all_required_present() -> None:
    control = ControlDefinition(
        control_id="T-SAST",
        framework=ControlFramework.NIST_SSDF,
        name="SAST",
        description="test",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=[EvidenceType.SAST_SCAN],
    )
    evaluation, gaps = evaluate_control(control, [_evidence(EvidenceType.SAST_SCAN)])
    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert not gaps


def test_control_missing_when_required_absent() -> None:
    control = ControlDefinition(
        control_id="T-SBOM",
        framework=ControlFramework.NIST_SSDF,
        name="SBOM",
        description="test",
        criticality=ControlCriticality.CRITICAL,
        required_evidence_types=[EvidenceType.SBOM],
    )
    evaluation, gaps = evaluate_control(control, [])
    assert evaluation.evaluation_status == ControlEvaluationStatus.MISSING
    assert len(gaps) == 1
    assert gaps[0].criticality == ControlCriticality.CRITICAL


def test_control_partial_when_recommended_missing() -> None:
    control = ControlDefinition(
        control_id="T-REVIEW",
        framework=ControlFramework.ORG_INTERNAL,
        name="Review",
        description="test",
        criticality=ControlCriticality.CRITICAL,
        required_evidence_types=[EvidenceType.CODE_REVIEW],
        recommended_evidence_types=[EvidenceType.PR_METADATA],
    )
    evaluation, gaps = evaluate_control(control, [_evidence(EvidenceType.CODE_REVIEW)])
    assert evaluation.evaluation_status == ControlEvaluationStatus.PARTIAL
    assert gaps
    assert all(g.criticality == ControlCriticality.LOW for g in gaps)


def test_manual_evidence_downgrades_confidence() -> None:
    control = ControlDefinition(
        control_id="T-APPROVE",
        framework=ControlFramework.ORG_INTERNAL,
        name="Release approval",
        description="test",
        criticality=ControlCriticality.CRITICAL,
        required_evidence_types=[EvidenceType.RELEASE_APPROVAL],
    )
    manual_ev = _evidence(
        EvidenceType.RELEASE_APPROVAL,
        confidence=ConfidenceLevel.MEDIUM,
        manual=True,
    )
    evaluation, _ = evaluate_control(control, [manual_ev])
    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert evaluation.confidence == ConfidenceLevel.LOW


def test_full_catalog_evaluation_against_complete_evidence() -> None:
    catalog = default_catalog()
    evidence = [
        _evidence(EvidenceType.SAST_SCAN),
        _evidence(EvidenceType.SCA_SCAN),
        _evidence(EvidenceType.SECRETS_SCAN),
        _evidence(EvidenceType.SBOM, status=EvidenceStatus.GENERATED),
        _evidence(EvidenceType.TEST_RESULT),
        _evidence(EvidenceType.CODE_REVIEW),
        _evidence(EvidenceType.PR_METADATA),
        _evidence(EvidenceType.THREAT_MODEL),
        _evidence(EvidenceType.RELEASE_APPROVAL),
        _evidence(EvidenceType.ROLLBACK_PLAN),
        _evidence(EvidenceType.ARTIFACT_SIGNATURE),
        _evidence(EvidenceType.ARTIFACT_ATTESTATION),
    ]
    evaluations, gaps = evaluate_controls(catalog, evidence)
    assert len(evaluations) == len(catalog)
    assert all(e.evaluation_status == ControlEvaluationStatus.MET for e in evaluations)
    assert not gaps
