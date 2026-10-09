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


# A record that is present but did not satisfy (failed, invalid) never changes
# the verdict: every required type needs one satisfying record. It used to be
# dropped in silence, though, so a failing safety suite next to a passing one,
# or next to an lm-eval file (always `generated`), left a `met` control whose
# rationale never mentioned it. The rationale now names such records.


def _named(
    evidence_type: EvidenceType,
    evidence_id: str,
    status: EvidenceStatus = EvidenceStatus.PASSED,
) -> NormalizedEvidence:
    return _evidence(evidence_type, status=status).model_copy(update={"evidence_id": evidence_id})


def _safety_control(
    *,
    required: tuple[EvidenceType, ...] = (EvidenceType.AI_SAFETY_EVAL,),
    recommended: tuple[EvidenceType, ...] = (),
) -> ControlDefinition:
    return ControlDefinition(
        control_id="T-SAFETY",
        framework=ControlFramework.NIST_SSDF,
        name="Safety evaluation",
        description="test",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=list(required),
        recommended_evidence_types=list(recommended),
    )


def test_a_met_rationale_names_a_failed_record_beside_a_passing_one() -> None:
    passing = _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-pass")
    failing = _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-fail", EvidenceStatus.FAILED)

    evaluation, gaps = evaluate_control(_safety_control(), [failing, passing])

    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert evaluation.evidence_refs == ["promptfoo-pass"]
    assert evaluation.confidence == ConfidenceLevel.HIGH
    assert not gaps
    assert evaluation.rationale == (
        "Control T-SAFETY is met by evidence promptfoo-pass. "
        "Evidence promptfoo-fail (failed) of type ai_safety_eval did not count."
    )


def test_a_partial_rationale_names_failed_and_invalid_records_of_both_kinds() -> None:
    control = _safety_control(recommended=(EvidenceType.MODEL_CARD,))
    evidence = [
        _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-pass"),
        _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-fail", EvidenceStatus.FAILED),
        _named(EvidenceType.MODEL_CARD, "card-1", EvidenceStatus.INVALID),
    ]

    evaluation, gaps = evaluate_control(control, evidence)

    assert evaluation.evaluation_status == ControlEvaluationStatus.PARTIAL
    assert evaluation.evidence_refs == ["promptfoo-pass"]
    assert evaluation.missing_recommended_evidence_types == [EvidenceType.MODEL_CARD]
    assert evaluation.rationale == (
        "Control T-SAFETY is partially satisfied: required evidence is present, "
        "but recommended evidence card-1 (invalid) of type model_card is present "
        "but did not satisfy it. "
        "Evidence promptfoo-fail (failed) of type ai_safety_eval did not count."
    )
    assert [g.description for g in gaps] == [
        "Recommended evidence `model_card` for control T-SAFETY is present but did "
        "not satisfy it: card-1 (invalid). Control is still considered partial."
    ]
    assert "Produce and attach" not in (gaps[0].remediation or "")


def test_a_missing_rationale_says_a_failed_record_is_present_but_did_not_satisfy() -> None:
    failing = _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-fail", EvidenceStatus.FAILED)

    evaluation, gaps = evaluate_control(_safety_control(), [failing])

    assert evaluation.evaluation_status == ControlEvaluationStatus.MISSING
    assert evaluation.evidence_refs == []
    assert evaluation.missing_required_evidence_types == [EvidenceType.AI_SAFETY_EVAL]
    assert evaluation.confidence == ConfidenceLevel.LOW
    assert evaluation.rationale == (
        "Control T-SAFETY is not satisfied: required evidence promptfoo-fail (failed) "
        "of type ai_safety_eval is present but did not satisfy it."
    )
    assert [g.description for g in gaps] == [
        "Required evidence `ai_safety_eval` for control T-SAFETY (Safety evaluation) "
        "is present but did not satisfy it: promptfoo-fail (failed)."
    ]
    # Attaching the same result again cannot help; the remediation says what can.
    assert [g.remediation for g in gaps] == [
        "`ai_safety_eval` evidence promptfoo-fail (failed) is present but did not "
        "satisfy control T-SAFETY. Resolve the cause (for a scan, remediate or waive "
        "its blocking findings) and collect it again."
    ]


def test_gaps_for_absent_evidence_keep_their_wording() -> None:
    """Only present-but-failed records get the new text; absent types do not move."""
    control = _safety_control(recommended=(EvidenceType.MODEL_CARD,))

    _evaluation, gaps = evaluate_control(control, [])

    assert [(g.description, g.remediation) for g in gaps] == [
        (
            "Required evidence `ai_safety_eval` for control T-SAFETY (Safety evaluation) "
            "is missing or failed validation.",
            "Produce and attach a `ai_safety_eval` evidence for this release to satisfy "
            "control T-SAFETY.",
        ),
        (
            "Recommended evidence `model_card` for control T-SAFETY is missing. "
            "Control is still considered partial.",
            "Produce and attach a `model_card` evidence for this release to satisfy "
            "control T-SAFETY.",
        ),
    ]


def test_a_missing_rationale_keeps_absent_types_apart_from_failed_ones() -> None:
    control = _safety_control(required=(EvidenceType.AI_SAFETY_EVAL, EvidenceType.MODEL_CARD))
    failing = _named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-fail", EvidenceStatus.FAILED)

    evaluation, _ = evaluate_control(control, [failing])

    assert evaluation.rationale == (
        "Control T-SAFETY is not satisfied: missing required evidence types model_card; "
        "required evidence promptfoo-fail (failed) of type ai_safety_eval is present "
        "but did not satisfy it."
    )


def test_rationales_without_unsatisfying_records_keep_their_wording() -> None:
    met, _ = evaluate_control(
        _safety_control(), [_named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-pass")]
    )
    missing, _ = evaluate_control(_safety_control(), [])

    assert met.rationale == "Control T-SAFETY is met by evidence promptfoo-pass."
    assert missing.rationale == (
        "Control T-SAFETY is not satisfied: missing required evidence types ai_safety_eval."
    )


def test_many_failed_records_keep_the_rationale_within_the_cap() -> None:
    evidence = [
        _named(EvidenceType.AI_SAFETY_EVAL, f"promptfoo-{index:04d}", EvidenceStatus.FAILED)
        for index in range(400)
    ]
    evidence.append(_named(EvidenceType.AI_SAFETY_EVAL, "promptfoo-pass"))

    evaluation, _ = evaluate_control(_safety_control(), evidence)

    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert evaluation.evidence_refs == ["promptfoo-pass"]
    assert len(evaluation.rationale) <= 2000
    assert "promptfoo-0000 (failed)" in evaluation.rationale
    assert "more; see the structured fields" in evaluation.rationale


# ---------------------------------------------------------------------------
# The satisfying-status allowlist is closed (D42)
#
# Widening `_SATISFYING_STATUSES` with UNKNOWN or MISSING survived the whole
# suite on 4.0.0: a record the engine could not classify, or one that says it
# is missing, would then meet a control. The allowlist is written out here on
# purpose, and the negative cases are the enum minus that literal, so a new
# member or a widened allowlist fails rather than silently joining the set.
# ---------------------------------------------------------------------------

_EXPECTED_SATISFYING = frozenset(
    {EvidenceStatus.PASSED, EvidenceStatus.COMPLETED, EvidenceStatus.GENERATED}
)
_NON_SATISFYING = sorted(set(EvidenceStatus) - _EXPECTED_SATISFYING)


def _single_required_control() -> ControlDefinition:
    return ControlDefinition(
        control_id="T-ALLOWLIST",
        framework=ControlFramework.NIST_SSDF,
        name="Allowlist",
        description="test",
        criticality=ControlCriticality.CRITICAL,
        required_evidence_types=[EvidenceType.SAST_SCAN],
    )


def test_non_satisfying_statuses_cover_the_rest_of_the_enum() -> None:
    assert _NON_SATISFYING
    assert {EvidenceStatus.UNKNOWN, EvidenceStatus.MISSING} <= set(_NON_SATISFYING)


@pytest.mark.parametrize("status", _NON_SATISFYING, ids=str)
def test_a_record_outside_the_allowlist_never_meets_a_control(status: EvidenceStatus) -> None:
    control = _single_required_control()
    evaluation, gaps = evaluate_control(control, [_evidence(EvidenceType.SAST_SCAN, status=status)])
    assert evaluation.evaluation_status == ControlEvaluationStatus.MISSING
    assert evaluation.missing_required_evidence_types == [EvidenceType.SAST_SCAN]
    assert evaluation.evidence_refs == []
    assert [g.criticality for g in gaps] == [ControlCriticality.CRITICAL]
    assert f"({status.value})" in evaluation.rationale


@pytest.mark.parametrize("status", sorted(_EXPECTED_SATISFYING))
def test_a_record_inside_the_allowlist_meets_a_control(status: EvidenceStatus) -> None:
    control = _single_required_control()
    evaluation, gaps = evaluate_control(control, [_evidence(EvidenceType.SAST_SCAN, status=status)])
    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert not gaps
