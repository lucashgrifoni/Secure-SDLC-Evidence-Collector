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
- Records of a required or recommended type that did not satisfy never change
  the verdict, but the rationale names each of them with its status, so a
  failed run next to a passing one is still visible in the evaluation.
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


def _note_unsatisfying(
    candidates: Sequence[NormalizedEvidence], noted: list[NormalizedEvidence]
) -> None:
    """Add the candidates that are present but did not satisfy, once each."""
    seen = {e.evidence_id for e in noted}
    for candidate in candidates:
        if not _is_satisfying(candidate) and candidate.evidence_id not in seen:
            noted.append(candidate)
            seen.add(candidate.evidence_id)


def _describe_unsatisfying(records: Sequence[NormalizedEvidence]) -> str:
    return _summarize(
        [f"{e.evidence_id} ({e.status.value}) of type {e.evidence_type.value}" for e in records]
    )


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


def _remediation_hint(
    control: ControlDefinition,
    evidence_type: EvidenceType | None,
    present: Sequence[NormalizedEvidence] = (),
) -> str:
    if evidence_type is None:
        return f"Provide evidence satisfying control {control.control_id}."
    if present:
        # The record exists and did not satisfy: producing and attaching
        # another one of the same result changes nothing.
        return _fit(
            f"`{evidence_type.value}` evidence {_records(present)} is present but did "
            f"not satisfy control {control.control_id}. Resolve the cause (for a scan, "
            f"remediate or waive its blocking findings) and collect it again.",
            _GAP_DESCRIPTION_LIMIT,
        )
    return (
        f"Produce and attach a `{evidence_type.value}` evidence for this "
        f"release to satisfy control {control.control_id}."
    )


def _records(records: Sequence[NormalizedEvidence]) -> str:
    return _summarize([f"{e.evidence_id} ({e.status.value})" for e in records])


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
    unsatisfying: list[NormalizedEvidence] = []
    gaps: list[Gap] = []

    for evidence_type in control.required_evidence_types:
        candidates = _select_by_type(evidence, evidence_type)
        satisfying = [e for e in candidates if _is_satisfying(e)]
        _note_unsatisfying(candidates, unsatisfying)
        if not satisfying:
            missing_required.append(evidence_type)
            # Records of the type exist but none satisfied: say so and name
            # them, rather than describing a scan that ran as an absent one.
            state = (
                f"is present but did not satisfy it: {_records(candidates)}."
                if candidates
                else "is missing or failed validation."
            )
            gaps.append(
                Gap(
                    control_id=control.control_id,
                    evidence_type=evidence_type,
                    criticality=control.criticality,
                    description=_fit(
                        f"Required evidence `{evidence_type.value}` for control "
                        f"{control.control_id} ({control.name}) {state}",
                        _GAP_DESCRIPTION_LIMIT,
                    ),
                    remediation=_remediation_hint(control, evidence_type, candidates),
                )
            )
            continue
        for candidate in satisfying:
            supporting_refs.append(candidate.evidence_id)
            supporting_evidence.append(candidate)

    for evidence_type in control.recommended_evidence_types:
        candidates = _select_by_type(evidence, evidence_type)
        satisfying = [e for e in candidates if _is_satisfying(e)]
        _note_unsatisfying(candidates, unsatisfying)
        if not satisfying:
            missing_recommended.append(evidence_type)
            state = (
                f"is present but did not satisfy it: {_records(candidates)}."
                if candidates
                else "is missing."
            )
            gaps.append(
                Gap(
                    control_id=control.control_id,
                    evidence_type=evidence_type,
                    criticality=ControlCriticality.LOW,
                    description=_fit(
                        f"Recommended evidence `{evidence_type.value}` for control "
                        f"{control.control_id} {state} Control is still "
                        f"considered partial.",
                        _GAP_DESCRIPTION_LIMIT,
                    ),
                    remediation=_remediation_hint(control, evidence_type, candidates),
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
            f"{_summarize(exception_refs)} "
            f"(approver={applicable_exceptions[0].approver}, "
            f"expires_at={applicable_exceptions[0].expires_at.isoformat()}). "
            f"Missing evidence would otherwise have been "
            f"{_summarize([t.value for t in missing_required])}."
        )
        # Waived gaps must not block the release; downgrade criticality.
        waived_by = _summarize(exception_refs)
        gaps = [
            Gap(
                control_id=gap.control_id,
                evidence_type=gap.evidence_type,
                criticality=ControlCriticality.LOW,
                description=_fit(
                    f"{gap.description} (waived by {waived_by}).", _GAP_DESCRIPTION_LIMIT
                ),
                remediation=gap.remediation,
            )
            for gap in gaps
        ]
    elif missing_required:
        status = ControlEvaluationStatus.MISSING
        # A required type with records that all failed is not absent: say so,
        # and name the records, instead of calling the type missing.
        absent = [t for t in missing_required if not _select_by_type(evidence, t)]
        present = [e for e in unsatisfying if e.evidence_type in missing_required]
        reasons: list[str] = []
        if absent:
            reasons.append(
                f"missing required evidence types {_summarize([t.value for t in absent])}"
            )
        if present:
            reasons.append(
                f"required evidence {_describe_unsatisfying(present)} is present "
                f"but did not satisfy it"
            )
        rationale = f"Control {control.control_id} is not satisfied: {'; '.join(reasons)}."
        rejected = _rejected_exceptions_for(
            control.control_id, exceptions, application, release_id, now
        )
        if rejected:
            rationale += (
                f" An exception was supplied for this control but did not apply: "
                f"{_summarize(rejected, separator='; ')}."
            )
        confidence = ConfidenceLevel.LOW
    elif missing_recommended:
        status = ControlEvaluationStatus.PARTIAL
        base_confidence = _lowest_confidence(supporting_evidence)
        confidence = _downgrade_if_manual(base_confidence, supporting_evidence)
        absent_rec = [t for t in missing_recommended if not _select_by_type(evidence, t)]
        present_rec = [e for e in unsatisfying if e.evidence_type in missing_recommended]
        lacking: list[str] = []
        if absent_rec:
            lacking.append(
                f"recommended evidence {_summarize([t.value for t in absent_rec])} is missing"
            )
        if present_rec:
            lacking.append(
                f"recommended evidence {_describe_unsatisfying(present_rec)} is present "
                f"but did not satisfy it"
            )
            # Named once: the closing sentence lists only the other records.
            unsatisfying = [e for e in unsatisfying if e not in present_rec]
        rationale = (
            f"Control {control.control_id} is partially satisfied: required "
            f"evidence is present, but {'; '.join(lacking)}."
        )
    else:
        status = ControlEvaluationStatus.MET
        base_confidence = _lowest_confidence(supporting_evidence)
        confidence = _downgrade_if_manual(base_confidence, supporting_evidence)
        rationale = (
            f"Control {control.control_id} is met by evidence {_summarize(supporting_refs)}."
        )

    if unsatisfying and status in (ControlEvaluationStatus.MET, ControlEvaluationStatus.PARTIAL):
        rationale += f" Evidence {_describe_unsatisfying(unsatisfying)} did not count."

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
        # `_summarize` keeps each list within its own budget; `_fit` makes the
        # bound unconditional, so no future edit to the prose above can
        # reintroduce a run that exits 3 with nothing written.
        rationale=_fit(rationale, _RATIONALE_LIMIT),
        exception_refs=exception_refs,
    )
    return evaluation, gaps


# The domain model caps these prose fields. Every branch below renders a list
# of ids or types into a sentence, and any of those lists can be long for
# perfectly ordinary reasons: a monorepo with one SARIF per service, a shared
# org-wide `--exceptions-dir` where every application has its own scoped waiver
# for the same control, a custom catalog. When the sentence crossed its cap,
# pydantic raised a ValidationError at the very end of the run and `run` exited
# 3 having written no bundle, no report and no summary at all.
#
# An earlier attempt capped the number of ids in one branch. That was the wrong
# unit and the wrong scope: `evidence_id` is `max_length=200` in the model, so
# even twenty of them can overflow, and six other joins were left unbounded.
# The budget is therefore in CHARACTERS, and `_fit` is applied to every string
# that a capped field receives — so the guarantee holds whatever new prose is
# added later. The structured fields (`evidence_refs`,
# `missing_required_evidence_types`, `exception_refs`) carry the complete,
# uncapped lists, so summarising the sentence loses nothing.
_RATIONALE_LIMIT = 2000
_GAP_DESCRIPTION_LIMIT = 1000

#: Characters of a capped field the list may occupy, leaving room for the
#: sentence built around it.
_LIST_BUDGET = 900

_ELLIPSIS = "…"


def _fit(text: str, limit: int) -> str:
    """Return `text` guaranteed to fit `limit` characters, marked if shortened.

    The last line of defence. `_summarize` keeps the prose readable; this makes
    the bound true no matter what is interpolated around it.
    """
    if len(text) <= limit:
        return text
    marker = f"{_ELLIPSIS} (truncated)"
    return text[: limit - len(marker)] + marker


def _summarize(items: Sequence[str], *, budget: int = _LIST_BUDGET, separator: str = ", ") -> str:
    """Join `items` within a character budget, naming how many were dropped."""
    shown: list[str] = []
    used = 0
    for index, item in enumerate(items):
        cost = len(item) + (len(separator) if index else 0)
        if used + cost > budget:
            break
        shown.append(item)
        used += cost
    if len(shown) == len(items):
        return separator.join(items)
    dropped = len(items) - len(shown)
    return f"{separator.join(shown)} (+{dropped} more; see the structured fields)"


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
