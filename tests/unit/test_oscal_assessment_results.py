"""Unit tests for the OSCAL Assessment Results exporter."""

from __future__ import annotations

import uuid

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
    ControlEvaluation,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.oscal import export_oscal_assessment_results


def _evaluation(
    control_id: str,
    status: ControlEvaluationStatus,
    *,
    criticality: ControlCriticality = ControlCriticality.HIGH,
    framework: ControlFramework = ControlFramework.NIST_SSDF,
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=framework,
        control_name=f"{control_id} name",
        evaluation_status=status,
        criticality=criticality,
        evidence_refs=["sca-1"],
        confidence=ConfidenceLevel.HIGH,
        rationale=f"{control_id} evaluated as {status.value}",
    )


def _bundle(evaluations: list[ControlEvaluation]) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-oscal-ar-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.18", commit_sha="abcdef1234567890"),
        evidence=[
            NormalizedEvidence(
                evidence_id="sca-1",
                evidence_type=EvidenceType.SCA_SCAN,
                source=EvidenceSource(name="trivy", kind="sarif"),
                producer="trivy",
                subject_type=SubjectType.COMMIT,
                subject_ref="abcdef1234567890",
                status=EvidenceStatus.GENERATED,
                confidence=ConfidenceLevel.HIGH,
                release_id="2026.05.18",
                commit_sha="abcdef1234567890",
            )
        ],
        control_evaluations=evaluations,
        gaps=[],
        exceptions=[],
        summary=Summary(
            total_controls=len(evaluations),
            controls_met=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.MET
            ),
            controls_partial=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.PARTIAL
            ),
            controls_missing=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.MISSING
            ),
            controls_waived=0,
            controls_not_applicable=0,
            release_status=ReleaseStatus.READY,
            evidence_coverage_score=0,
            confidence_score=0,
        ),
    )


def test_assessment_results_shape_matches_oscal_1_1_2() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    doc = export_oscal_assessment_results(bundle)

    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert uuid.UUID(ar["uuid"])
    assert ar["results"][0]["title"].startswith("Release ")


def test_assessment_results_maps_status_to_oscal_state() -> None:
    bundle = _bundle(
        [
            _evaluation("SSDF-PW.4", ControlEvaluationStatus.MET),
            _evaluation("SSDF-PS.2", ControlEvaluationStatus.MISSING),
            _evaluation("SSDF-PW.1", ControlEvaluationStatus.PARTIAL),
        ]
    )
    findings = export_oscal_assessment_results(bundle)["assessment-results"]["results"][0][
        "findings"
    ]
    states = {f["props"][0]["value"]: f["target"]["status"]["state"] for f in findings}
    assert states["SSDF-PW.4"] == "satisfied"
    assert states["SSDF-PS.2"] == "not-satisfied"
    assert states["SSDF-PW.1"] == "not-satisfied"


def test_assessment_results_uuids_are_stable_across_runs() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    first = export_oscal_assessment_results(bundle)
    second = export_oscal_assessment_results(bundle)
    assert first["assessment-results"]["uuid"] == second["assessment-results"]["uuid"]
    assert (
        first["assessment-results"]["results"][0]["findings"][0]["uuid"]
        == second["assessment-results"]["results"][0]["findings"][0]["uuid"]
    )


def test_assessment_results_records_release_status_prop() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    props = export_oscal_assessment_results(bundle)["assessment-results"]["metadata"]["props"]
    names = {p["name"]: p["value"] for p in props}
    assert names["release_id"] == "2026.05.18"
    assert names["release_status"] == ReleaseStatus.READY.value


def test_assessment_results_emits_one_finding_per_evaluation() -> None:
    bundle = _bundle(
        [
            _evaluation("SSDF-PW.4", ControlEvaluationStatus.MET),
            _evaluation("SSDF-PS.2", ControlEvaluationStatus.MISSING),
        ]
    )
    findings = export_oscal_assessment_results(bundle)["assessment-results"]["results"][0][
        "findings"
    ]
    assert len(findings) == 2
    target_ids = sorted(f["target"]["target-id"] for f in findings)
    assert target_ids == ["ssdf-ps-2", "ssdf-pw-4"]
