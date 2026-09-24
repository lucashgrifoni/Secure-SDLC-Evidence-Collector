"""Unit tests for the controls engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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
    EvidenceException,
    EvidenceSource,
    ExceptionScope,
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
        _evidence(EvidenceType.DAST_SCAN),
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


def test_met_rationale_stays_within_the_domain_cap_for_large_evidence_sets() -> None:
    """A big-but-legitimate evidence set must not abort the whole run.

    `rationale` is capped at 2000 characters by the domain model, and the MET
    branch used to join every supporting evidence id into that sentence. Around
    104 artifacts of a single type the string crossed the cap, pydantic raised
    a ValidationError, and `run` exited 3 having written no bundle, report or
    summary at all — a monorepo with one SARIF per service is not a malformed
    input. `evidence_refs` still carries the complete list.
    """
    control = ControlDefinition(
        control_id="T-MANY",
        framework=ControlFramework.NIST_SSDF,
        name="Static analysis",
        description="Run SAST.",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=[EvidenceType.SAST_SCAN],
    )
    evidence = []
    for index in range(400):
        item = _evidence(EvidenceType.SAST_SCAN)
        evidence.append(item.model_copy(update={"evidence_id": f"ev-sast-{index:04d}"}))

    evaluation, gaps = evaluate_control(control, evidence)

    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert not gaps
    assert len(evaluation.rationale) <= 2000
    assert len(evaluation.evidence_refs) == 400
    assert "ev-sast-0000" in evaluation.rationale
    assert "more; see the structured fields" in evaluation.rationale


def test_small_evidence_sets_still_list_every_id_in_the_rationale() -> None:
    """The summary must not kick in early and hide ids an auditor can read."""
    control = ControlDefinition(
        control_id="T-FEW",
        framework=ControlFramework.NIST_SSDF,
        name="Static analysis",
        description="Run SAST.",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=[EvidenceType.SAST_SCAN],
    )
    evidence = [
        _evidence(EvidenceType.SAST_SCAN).model_copy(update={"evidence_id": f"ev-{i}"})
        for i in range(5)
    ]

    evaluation, _ = evaluate_control(control, evidence)

    assert "more; see evidence_refs" not in evaluation.rationale
    for index in range(5):
        assert f"ev-{index}" in evaluation.rationale


def _waiver(index: int, *, other_app: bool, id_length: int = 8) -> EvidenceException:
    approved = datetime(2026, 4, 10, tzinfo=UTC)
    return EvidenceException(
        exception_id=f"EXC-{index:04d}".ljust(id_length, "x"),
        control_id="T-CAP",
        approver="appsec-lead@example.com",
        approved_at=approved,
        expires_at=approved + timedelta(days=365),
        justification="No new trust boundary; follow-up scheduled next quarter.",
        scope=ExceptionScope(application="another-app" if other_app else None),
    )


def _capped_control(recommended: int = 0) -> ControlDefinition:
    return ControlDefinition(
        control_id="T-CAP",
        framework=ControlFramework.NIST_SSDF,
        name="Static analysis",
        description="Run SAST.",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=[EvidenceType.SAST_SCAN],
        recommended_evidence_types=[EvidenceType.SBOM] * recommended,
    )


@pytest.mark.parametrize(
    ("label", "recommended", "waiver_count", "other_app", "id_length"),
    [
        # A shared org-wide --exceptions-dir: every other application has its
        # own correctly-scoped waiver for this control, so all of them land in
        # this control's "did not apply" list. Crashed at 41.
        ("missing/rejected", 0, 500, True, 8),
        # Many valid waivers for one control: the WAIVED rationale and the
        # waived Gap.description (cap 1000) both join every id. Crashed at 89.
        ("waived/applicable", 0, 500, False, 8),
        # A custom catalog listing a recommended type repeatedly — nothing
        # dedupes `recommended_evidence_types`.
        ("partial/duplicates", 200, 0, False, 8),
        # `exception_id` is max_length=100 in the model, so a count-based cap
        # is the wrong unit even for a short list.
        ("missing/long-ids", 0, 200, True, 100),
    ],
)
def test_no_branch_can_overflow_a_capped_prose_field(
    label: str, recommended: int, waiver_count: int, other_app: bool, id_length: int
) -> None:
    """Every rationale branch must survive a large but perfectly ordinary input.

    `rationale` is capped at 2000 characters and `Gap.description` at 1000. Each
    branch renders a list into its sentence, and when the sentence crossed the
    cap pydantic raised at the very end of the run: `run` exited 3 having
    written no bundle, no report and no summary at all.

    An earlier fix capped the *number* of ids in the MET branch only. That was
    the wrong unit — ids are `max_length=200`, so twenty can overflow — and the
    wrong scope, since six other joins were left unbounded. Each case here
    crashed before the budget became character-based and unconditional.
    """
    exceptions = [_waiver(i, other_app=other_app, id_length=id_length) for i in range(waiver_count)]

    evaluation, gaps = evaluate_control(
        _capped_control(recommended),
        [],
        exceptions=exceptions,
        application="the-app-being-released",
        release_id="1.0.0",
        now=datetime(2026, 4, 11, tzinfo=UTC),
    )

    assert len(evaluation.rationale) <= 2000, label
    for gap in gaps:
        assert len(gap.description) <= 1000, label
        assert gap.remediation is None or len(gap.remediation) <= 1000, label


def test_truncation_is_marked_rather_than_silent() -> None:
    """A shortened sentence must say so; a silently cut one reads as complete."""
    control = _capped_control()
    exceptions = [_waiver(i, other_app=True, id_length=100) for i in range(200)]

    evaluation, _ = evaluate_control(
        control,
        [],
        exceptions=exceptions,
        application="the-app-being-released",
        release_id="1.0.0",
        now=datetime(2026, 4, 11, tzinfo=UTC),
    )

    assert "more; see the structured fields" in evaluation.rationale
    # The complete list is still available in structured form.
    assert evaluation.evaluation_status == ControlEvaluationStatus.MISSING
