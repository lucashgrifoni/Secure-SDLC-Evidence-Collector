"""Unit tests for the OSCAL Assessment Results exporter."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

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
    EvidenceException,
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


def _bundle(
    evaluations: list[ControlEvaluation],
    exceptions: list[EvidenceException] | None = None,
) -> EvidenceBundle:
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
        exceptions=exceptions or [],
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
            controls_waived=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.WAIVED
            ),
            controls_not_applicable=sum(
                1
                for e in evaluations
                if e.evaluation_status is ControlEvaluationStatus.NOT_APPLICABLE
            ),
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


# ---------------------------------------------------------------------------
# WAIVED and NOT_APPLICABLE are not a clean pass. OSCAL's objective-status
# state is only `satisfied` / `not-satisfied`, so both go to `not-satisfied`
# with the reason preserved; a waiver is additionally recorded as an OSCAL
# risk with status `deviation-approved` that names the exception, matching
# the SVR exporter, which never asserts a waived control as verified.
# ---------------------------------------------------------------------------


def _waiver(exception_id: str, control_id: str) -> EvidenceException:
    return EvidenceException(
        exception_id=exception_id,
        control_id=control_id,
        approver="security-lead@acme.example",
        approved_at=datetime(2026, 5, 1, tzinfo=UTC),
        expires_at=datetime(2026, 8, 1, tzinfo=UTC),
        justification="Threat model refresh scheduled for the next quarter.",
        reference="SEC-1234",
    )


def _results(doc: dict) -> dict:
    return doc["assessment-results"]["results"][0]


def _finding(doc: dict, control_id: str) -> dict:
    return next(
        f
        for f in _results(doc)["findings"]
        if {"name": "control_id", "value": control_id} in f["props"]
    )


def test_waived_control_is_not_satisfied_and_records_the_waiver() -> None:
    waived = _evaluation("SSDF-PW.1", ControlEvaluationStatus.WAIVED).model_copy(
        update={"exception_refs": ["EXC-7"]}
    )
    bundle = _bundle([waived], [_waiver("EXC-7", "SSDF-PW.1")])
    doc = export_oscal_assessment_results(bundle)
    finding = _finding(doc, "SSDF-PW.1")

    assert finding["target"]["status"]["state"] == "not-satisfied"
    assert {"name": "exception_id", "value": "EXC-7"} in finding["props"]
    assert {"name": "not_satisfied_reason", "value": "waived"} in finding["props"]

    risks = {r["uuid"]: r for r in _results(doc)["risks"]}
    related = [r["risk-uuid"] for r in finding["related-risks"]]
    assert len(related) == 1
    risk = risks[related[0]]
    assert risk["status"] == "deviation-approved"
    assert {"name": "exception_id", "value": "EXC-7"} in risk["props"]
    assert risk["deadline"].startswith("2026-08-01T00:00:00")
    assert "Threat model refresh" in risk["description"]


def test_not_applicable_control_is_not_satisfied_without_a_risk() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.9", ControlEvaluationStatus.NOT_APPLICABLE)])
    doc = export_oscal_assessment_results(bundle)
    finding = _finding(doc, "SSDF-PW.9")
    assert finding["target"]["status"]["state"] == "not-satisfied"
    assert {"name": "not_satisfied_reason", "value": "not_applicable"} in finding["props"]
    assert "related-risks" not in finding
    assert "risks" not in _results(doc)


def test_met_control_carries_no_risk_or_reason() -> None:
    doc = export_oscal_assessment_results(
        _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    )
    finding = _finding(doc, "SSDF-PW.4")
    assert finding["target"]["status"]["state"] == "satisfied"
    assert "related-risks" not in finding
    assert all(p["name"] != "not_satisfied_reason" for p in finding["props"])
    assert "risks" not in _results(doc)
