"""Control evaluation engine.

For each control definition, gather the matching normalized evidence,
decide whether the control is `met`, `partial`, or `missing`, and emit
structured gaps that downstream scoring and reporting can consume.

Rules (kept intentionally simple and explainable):

- Every required evidence type must be present. Missing any of them yields
  `missing`. Present with `failed`/`invalid` status is treated as missing
  from the control's perspective, because the evidence does not demonstrate
  the control was satisfied.
- When all required types are satisfied but some recommended types are not,
  the control is `partial` and a non-blocking gap is emitted.
- When everything satisfied, the control is `met`.
- Evaluation confidence is the lowest confidence across the satisfying
  evidences, with a one-step downgrade if any supporting evidence is manual.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    EvidenceStatus,
    EvidenceType,
)
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    ControlEvaluation,
    EvidenceException,
    Gap,
    NormalizedEvidence,
    ReleaseContext,
)

_SATISFYING_STATUSES: frozenset[EvidenceStatus] = frozenset(
    {
        EvidenceStatus.PASSED,
        EvidenceStatus.COMPLETED,
        EvidenceStatus.GENERATED,
    }
)

_CONFIDENCE_RANK: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 3,
    ConfidenceLevel.MEDIUM: 2,
    ConfidenceLevel.LOW: 1,
}


def _select_by_type(
    evidence: Sequence[NormalizedEvidence], evidence_type: EvidenceType
) -> list[NormalizedEvidence]:
    return [e for e in evidence if e.evidence_type == evidence_type]


def _is_satisfying(evidence: NormalizedEvidence) -> bool:
    return evidence.status in _SATISFYING_STATUSES


def _lowest_confidence(
    supporting: Iterable[NormalizedEvidence],
) -> ConfidenceLevel:
    rank = min(
        (_CONFIDENCE_RANK[e.confidence] for e in supporting),
        default=_CONFIDENCE_RANK[ConfidenceLevel.MEDIUM],
    )
    for level, level_rank in _CONFIDENCE_RANK.items():
        if level_rank == rank:
            return level
    return ConfidenceLevel.MEDIUM


def _downgrade_if_manual(
    base: ConfidenceLevel, supporting: Iterable[NormalizedEvidence]
) -> ConfidenceLevel:
    if not any(e.manual for e in supporting):
        return base
    if base == ConfidenceLevel.HIGH:
        return ConfidenceLevel.MEDIUM
    if base == ConfidenceLevel.MEDIUM:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def _remediation_hint(control: ControlDefinition, evidence_type: EvidenceType | None) -> str:
    if evidence_type is None:
        return f"Provide evidence satisfying control {control.control_id}."
    return (
        f"Produce and attach a `{evidence_type.value}` evidence for this "
        f"release to satisfy control {control.control_id}."
    )


def _valid_exceptions_for(
    control_id: str,
    exceptions: Sequence[EvidenceException],
    application: str,
    release_id: str,
    now: datetime,
) -> list[EvidenceException]:
    return [
        exc
        for exc in exceptions
        if exc.control_id == control_id
        and exc.is_valid_for(application=application, release_id=release_id, now=now)
    ]


def _rejected_exceptions_for(
    control_id: str,
    exceptions: Sequence[EvidenceException],
    application: str,
    release_id: str,
    now: datetime,
) -> list[str]:
    """Describe waivers that name ``control_id`` but did not apply, and why.

    A waiver that is expired or out of scope was previously dropped in silence:
    it still appeared in ``bundle.exceptions`` but the control came out MISSING
    with an empty ``exception_refs`` and a rationale that never mentioned it.
    An auditor reading the bundle could not tell "nobody ever requested an
    exception" apart from "an exception was requested and refused" — a gap in
    the audit trail of a tool whose whole purpose is the audit trail.
    """
    reasons: list[str] = []
    for exc in exceptions:
        if exc.control_id != control_id:
            continue
        if exc.is_valid_for(application=application, release_id=release_id, now=now):
            continue
        if now >= exc.expires_at:
            why = f"expired {exc.expires_at.isoformat()}"
        elif now < exc.approved_at:
            why = f"not yet in effect, approved_at {exc.approved_at.isoformat()}"
        else:
            why = "out of scope for this application/release"
        reasons.append(f"{exc.exception_id} ({why})")
    return reasons


def evaluate_control(
    control: ControlDefinition,
    evidence: Sequence[NormalizedEvidence],
    *,
    exceptions: Sequence[EvidenceException] = (),
    application: str = "",
    release_id: str = "",
    now: datetime | None = None,
) -> tuple[ControlEvaluation, list[Gap]]:
    """Evaluate a single control and return its evaluation plus any gaps.

    When `exceptions` contains a valid (non-expired, in-scope) waiver for
    this control, the evaluation status becomes `WAIVED` and no blocking
    gap is emitted. Required-evidence gaps are still reported informally
    so the auditor sees what the waiver is compensating for.
    """
    now = now or datetime.now(tz=UTC)
    applicable_exceptions = _valid_exceptions_for(
        control.control_id, exceptions, application, release_id, now
    )
    supporting_refs: list[str] = []
    supporting_evidence: list[NormalizedEvidence] = []
    missing_required: list[EvidenceType] = []
    missing_recommended: list[EvidenceType] = []
    gaps: list[Gap] = []

    for evidence_type in control.required_evidence_types:
        candidates = _select_by_type(evidence, evidence_type)
        satisfying = [e for e in candidates if _is_satisfying(e)]
        if not satisfying:
            missing_required.append(evidence_type)
            gaps.append(
                Gap(
                    control_id=control.control_id,
                    evidence_type=evidence_type,
                    criticality=control.criticality,
                    description=(
                        f"Required evidence `{evidence_type.value}` for control "
                        f"{control.control_id} ({control.name}) is missing or "
                        f"failed validation."
                    ),
                    remediation=_remediation_hint(control, evidence_type),
                )
            )
            continue
        for candidate in satisfying:
            supporting_refs.append(candidate.evidence_id)
            supporting_evidence.append(candidate)

    for evidence_type in control.recommended_evidence_types:
        candidates = _select_by_type(evidence, evidence_type)
        satisfying = [e for e in candidates if _is_satisfying(e)]
        if not satisfying:
            missing_recommended.append(evidence_type)
            gaps.append(
                Gap(
                    control_id=control.control_id,
                    evidence_type=evidence_type,
                    criticality=ControlCriticality.LOW,
                    description=(
                        f"Recommended evidence `{evidence_type.value}` for control "
                        f"{control.control_id} is missing. Control is still "
                        f"considered partial."
                    ),
                    remediation=_remediation_hint(control, evidence_type),
                )
            )
            continue
        for candidate in satisfying:
            if candidate.evidence_id not in supporting_refs:
                supporting_refs.append(candidate.evidence_id)
                supporting_evidence.append(candidate)

    exception_refs: list[str] = [exc.exception_id for exc in applicable_exceptions]

    if missing_required and applicable_exceptions:
        # A valid waiver covers the gap: mark as WAIVED, keep the gap out of
        # the blocking list but keep missing types for auditor transparency.
        status = ControlEvaluationStatus.WAIVED
        confidence = ConfidenceLevel.LOW
        rationale = (
            f"Control {control.control_id} is waived by "
            f"{', '.join(exc.exception_id for exc in applicable_exceptions)} "
            f"(approver={applicable_exceptions[0].approver}, "
            f"expires_at={applicable_exceptions[0].expires_at.isoformat()}). "
            f"Missing evidence would otherwise have been "
            f"{', '.join(t.value for t in missing_required)}."
        )
        # Waived gaps must not block the release; downgrade criticality.
        gaps = [
            Gap(
                control_id=gap.control_id,
                evidence_type=gap.evidence_type,
                criticality=ControlCriticality.LOW,
                description=f"{gap.description} (waived by {', '.join(exception_refs)}).",
                remediation=gap.remediation,
            )
            for gap in gaps
        ]
    elif missing_required:
        status = ControlEvaluationStatus.MISSING
        rationale = (
            f"Control {control.control_id} is not satisfied: missing required "
            f"evidence types "
            f"{', '.join(t.value for t in missing_required)}."
        )
        rejected = _rejected_exceptions_for(
            control.control_id, exceptions, application, release_id, now
        )
        if rejected:
            rationale += (
                f" An exception was supplied for this control but did not apply: "
                f"{'; '.join(rejected)}."
            )
        confidence = ConfidenceLevel.LOW
    elif missing_recommended:
        status = ControlEvaluationStatus.PARTIAL
        base_confidence = _lowest_confidence(supporting_evidence)
        confidence = _downgrade_if_manual(base_confidence, supporting_evidence)
        rationale = (
            f"Control {control.control_id} is partially satisfied: required "
            f"evidence is present, but recommended evidence "
            f"{', '.join(t.value for t in missing_recommended)} is missing."
        )
    else:
        status = ControlEvaluationStatus.MET
        base_confidence = _lowest_confidence(supporting_evidence)
        confidence = _downgrade_if_manual(base_confidence, supporting_evidence)
        rationale = (
            f"Control {control.control_id} is met by evidence {_summarize_refs(supporting_refs)}."
        )

    evaluation = ControlEvaluation(
        control_id=control.control_id,
        framework=control.framework,
        control_name=control.name,
        evaluation_status=status,
        criticality=control.criticality,
        evidence_refs=supporting_refs,
        missing_required_evidence_types=missing_required,
        missing_recommended_evidence_types=missing_recommended,
        confidence=confidence,
        rationale=rationale,
        exception_refs=exception_refs,
    )
    return evaluation, gaps


# `rationale` is capped at 2000 characters by the domain model. Joining every
# supporting evidence id into the sentence blew that cap at ~104 artifacts of
# one type: pydantic raised ValidationError, `run` exited 3 and wrote NO
# bundle, report or summary at all. A large-but-legitimate evidence set is not
# a malformed input, and the prose is a human sentence — `evidence_refs`
# carries the complete, uncapped list, so nothing is lost by summarising here.
_MAX_RATIONALE_REFS = 20


def _summarize_refs(refs: list[str]) -> str:
    """Render evidence ids for prose, bounded so the sentence cannot overflow."""
    if len(refs) <= _MAX_RATIONALE_REFS:
        return ", ".join(refs)
    shown = ", ".join(refs[:_MAX_RATIONALE_REFS])
    return f"{shown} (+{len(refs) - _MAX_RATIONALE_REFS} more; see evidence_refs)"


def evaluate_controls(
    controls: Sequence[ControlDefinition],
    evidence: Sequence[NormalizedEvidence],
    *,
    exceptions: Sequence[EvidenceException] = (),
    application: Application | str | None = None,
    release: ReleaseContext | str | None = None,
    now: datetime | None = None,
) -> tuple[list[ControlEvaluation], list[Gap]]:
    """Evaluate every control against the evidence set, applying waivers.

    `application` and `release` may be either the rich domain objects or
    their string identifiers; a missing value disables scope matching for
    that dimension (which means only unscoped exceptions will apply).
    """
    app_id = application.name if isinstance(application, Application) else (application or "")
    release_id = release.release_id if isinstance(release, ReleaseContext) else (release or "")
    evaluations: list[ControlEvaluation] = []
    gaps: list[Gap] = []
    for control in controls:
        evaluation, control_gaps = evaluate_control(
            control,
            evidence,
            exceptions=exceptions,
            application=app_id,
            release_id=release_id,
            now=now,
        )
        evaluations.append(evaluation)
        gaps.extend(control_gaps)
    return evaluations, gaps
