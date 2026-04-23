"""Release scoring engine.

This module is intentionally small and explainable. Scores are not meant to
be marketed as a compliance number: they represent how much of the expected
evidence set is present and how confident the tool is about that evidence.

Scoring rules:

- Coverage score weights required evidence types at 1.0 and recommended ones
  at 0.5. A control that is fully met contributes all of its weight; partial
  contributes the weight of the satisfied items; missing contributes zero.
  The score is the ratio of earned weight over total weight, mapped to 0-100.
- Confidence score averages the numeric confidence (high=100, medium=66,
  low=33) across evaluations that are at least partially satisfied. When no
  evaluation is satisfied, the score is 0.
- Release status is derived from criticality of remaining gaps, not from the
  numeric score, so a "high score" cannot override a missing critical
  control.
"""

from __future__ import annotations

from collections.abc import Sequence

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ReleaseStatus,
)
from evidence_collector.domain.models import (
    ControlDefinition,
    ControlEvaluation,
    Gap,
    Summary,
)

_REQUIRED_WEIGHT = 1.0
_RECOMMENDED_WEIGHT = 0.5

_CONFIDENCE_TO_SCORE: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 100,
    ConfidenceLevel.MEDIUM: 66,
    ConfidenceLevel.LOW: 33,
}


def _coverage_for_control(
    control: ControlDefinition, evaluation: ControlEvaluation
) -> tuple[float, float]:
    """Return (earned, total) weight for a single control."""
    total_required = len(control.required_evidence_types) * _REQUIRED_WEIGHT
    total_recommended = len(control.recommended_evidence_types) * _RECOMMENDED_WEIGHT
    total = total_required + total_recommended
    if total == 0:
        return 0.0, 0.0

    if evaluation.evaluation_status == ControlEvaluationStatus.NOT_APPLICABLE:
        return 0.0, 0.0
    if evaluation.evaluation_status == ControlEvaluationStatus.WAIVED:
        return total, total

    missing_required_weight = len(evaluation.missing_required_evidence_types) * _REQUIRED_WEIGHT
    missing_recommended_weight = (
        len(evaluation.missing_recommended_evidence_types) * _RECOMMENDED_WEIGHT
    )
    earned = total - missing_required_weight - missing_recommended_weight
    if earned < 0:
        earned = 0.0
    return earned, total


def compute_coverage_score(
    controls: Sequence[ControlDefinition],
    evaluations: Sequence[ControlEvaluation],
) -> int:
    control_by_id = {c.control_id: c for c in controls}
    earned_total = 0.0
    total_total = 0.0
    for evaluation in evaluations:
        control = control_by_id.get(evaluation.control_id)
        if control is None:
            continue
        earned, total = _coverage_for_control(control, evaluation)
        earned_total += earned
        total_total += total
    if total_total == 0:
        return 0
    return round((earned_total / total_total) * 100)


def compute_confidence_score(evaluations: Sequence[ControlEvaluation]) -> int:
    relevant = [
        e
        for e in evaluations
        if e.evaluation_status
        in {
            ControlEvaluationStatus.MET,
            ControlEvaluationStatus.PARTIAL,
            ControlEvaluationStatus.WAIVED,
        }
    ]
    if not relevant:
        return 0
    total = sum(_CONFIDENCE_TO_SCORE[e.confidence] for e in relevant)
    return round(total / len(relevant))


def compute_release_status(
    evaluations: Sequence[ControlEvaluation],
    gaps: Sequence[Gap],
) -> ReleaseStatus:
    """Translate gaps and evaluations into a release readiness verdict."""
    has_critical_gap = any(
        gap.criticality == ControlCriticality.CRITICAL and _is_blocking_gap(gap, evaluations)
        for gap in gaps
    )
    if has_critical_gap:
        return ReleaseStatus.NOT_READY

    has_high_gap = any(
        gap.criticality == ControlCriticality.HIGH and _is_blocking_gap(gap, evaluations)
        for gap in gaps
    )
    if has_high_gap:
        return ReleaseStatus.CONDITIONAL

    any_partial_or_missing = any(
        e.evaluation_status
        in {
            ControlEvaluationStatus.PARTIAL,
            ControlEvaluationStatus.MISSING,
        }
        for e in evaluations
    )
    if any_partial_or_missing:
        return ReleaseStatus.CONDITIONAL

    return ReleaseStatus.READY


def _is_blocking_gap(gap: Gap, evaluations: Sequence[ControlEvaluation]) -> bool:
    """Only gaps tied to missing required evidence should block the release.

    Recommended-evidence gaps are degraded to low criticality by the engine,
    so they are never blocking by construction. This helper is a safety net
    for future changes.
    """
    if gap.criticality == ControlCriticality.LOW:
        return False
    for evaluation in evaluations:
        if evaluation.control_id != gap.control_id:
            continue
        if gap.evidence_type is None:
            return evaluation.evaluation_status in {
                ControlEvaluationStatus.MISSING,
                ControlEvaluationStatus.PARTIAL,
            }
        return gap.evidence_type in evaluation.missing_required_evidence_types
    return True


def _missing_critical_evidence(
    controls: Sequence[ControlDefinition],
    evaluations: Sequence[ControlEvaluation],
) -> list[str]:
    control_by_id = {c.control_id: c for c in controls}
    labels: list[str] = []
    for evaluation in evaluations:
        if evaluation.evaluation_status != ControlEvaluationStatus.MISSING:
            continue
        control = control_by_id.get(evaluation.control_id)
        if control is None:
            continue
        if control.criticality not in {
            ControlCriticality.CRITICAL,
            ControlCriticality.HIGH,
        }:
            continue
        for evidence_type in evaluation.missing_required_evidence_types:
            label = f"{control.control_id}:{evidence_type.value}"
            if label not in labels:
                labels.append(label)
    return labels


def _count_statuses(
    evaluations: Sequence[ControlEvaluation],
) -> tuple[int, int, int, int, int]:
    met = sum(1 for e in evaluations if e.evaluation_status == ControlEvaluationStatus.MET)
    partial = sum(1 for e in evaluations if e.evaluation_status == ControlEvaluationStatus.PARTIAL)
    missing = sum(1 for e in evaluations if e.evaluation_status == ControlEvaluationStatus.MISSING)
    waived = sum(1 for e in evaluations if e.evaluation_status == ControlEvaluationStatus.WAIVED)
    not_applicable = sum(
        1 for e in evaluations if e.evaluation_status == ControlEvaluationStatus.NOT_APPLICABLE
    )
    return met, partial, missing, waived, not_applicable


def build_summary(
    controls: Sequence[ControlDefinition],
    evaluations: Sequence[ControlEvaluation],
    gaps: Sequence[Gap],
) -> Summary:
    coverage = compute_coverage_score(controls, evaluations)
    confidence = compute_confidence_score(evaluations)
    release_status = compute_release_status(evaluations, gaps)
    missing_critical = _missing_critical_evidence(controls, evaluations)
    met, partial, missing, waived, not_applicable = _count_statuses(evaluations)
    return Summary(
        evidence_coverage_score=coverage,
        confidence_score=confidence,
        release_status=release_status,
        missing_critical_evidence=missing_critical,
        total_controls=len(evaluations),
        controls_met=met,
        controls_partial=partial,
        controls_missing=missing,
        controls_waived=waived,
        controls_not_applicable=not_applicable,
    )
