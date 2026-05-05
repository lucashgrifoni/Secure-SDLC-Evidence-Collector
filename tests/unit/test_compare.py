"""Behaviour tests for `application/compare.py`.

Covers the rank-based improvement/regression detection plus the
`to_dict` output contract the CLI emits as JSON. Avoids snapshotting
the Rich table rendering — the JSON shape is the public contract.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidence_collector.application.compare import (
    BundleComparison,
    ControlDelta,
    _is_improvement,
    _is_regression,
    compare_bundles,
    load_bundle,
)
from evidence_collector.domain.enums import (
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    ReleaseStatus,
)
from evidence_collector.domain.models import (
    Application,
    ControlEvaluation,
    EvidenceBundle,
    ReleaseContext,
    Summary,
)

_NOW = datetime(2026, 5, 5, tzinfo=UTC)


def _make_evaluation(
    control_id: str,
    *,
    status: ControlEvaluationStatus,
    criticality: ControlCriticality = ControlCriticality.HIGH,
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=ControlFramework.NIST_SSDF,
        control_name=control_id,
        evaluation_status=status,
        criticality=criticality,
        rationale="behaviour test fixture",
        evaluated_at=_NOW,
    )


def _summary(
    *,
    coverage: int,
    confidence: int,
    release_status: ReleaseStatus,
    evaluations: list[ControlEvaluation],
) -> Summary:
    counts = {
        ControlEvaluationStatus.MET: 0,
        ControlEvaluationStatus.PARTIAL: 0,
        ControlEvaluationStatus.MISSING: 0,
        ControlEvaluationStatus.WAIVED: 0,
        ControlEvaluationStatus.NOT_APPLICABLE: 0,
    }
    for ev in evaluations:
        counts[ev.evaluation_status] += 1
    return Summary(
        evidence_coverage_score=coverage,
        confidence_score=confidence,
        release_status=release_status,
        total_controls=len(evaluations),
        controls_met=counts[ControlEvaluationStatus.MET],
        controls_partial=counts[ControlEvaluationStatus.PARTIAL],
        controls_missing=counts[ControlEvaluationStatus.MISSING],
        controls_waived=counts[ControlEvaluationStatus.WAIVED],
        controls_not_applicable=counts[ControlEvaluationStatus.NOT_APPLICABLE],
    )


def _make_bundle(
    bundle_id: str,
    *,
    release_status: ReleaseStatus,
    coverage: int,
    confidence: int,
    evaluations: list[ControlEvaluation],
) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id=bundle_id,
        generated_at=_NOW,
        application=Application(name="x", repository="o/x"),
        release=ReleaseContext(release_id="r", commit_sha="0" * 16),
        evidence=[],
        control_evaluations=evaluations,
        summary=_summary(
            coverage=coverage,
            confidence=confidence,
            release_status=release_status,
            evaluations=evaluations,
        ),
    )


# ---------------------------------------------------------------------------
# _is_improvement / _is_regression — rank-based, None-tolerant.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("before", "after", "improved", "regressed"),
    [
        # Same status: neither
        (
            ControlEvaluationStatus.MET,
            ControlEvaluationStatus.MET,
            False,
            False,
        ),
        # MISSING -> MET is an improvement
        (
            ControlEvaluationStatus.MISSING,
            ControlEvaluationStatus.MET,
            True,
            False,
        ),
        # MET -> MISSING is a regression
        (
            ControlEvaluationStatus.MET,
            ControlEvaluationStatus.MISSING,
            False,
            True,
        ),
        # PARTIAL -> WAIVED counts as improvement (waived ranks above partial)
        (
            ControlEvaluationStatus.PARTIAL,
            ControlEvaluationStatus.WAIVED,
            True,
            False,
        ),
        # WAIVED -> MET is improvement (met ranks above waived)
        (
            ControlEvaluationStatus.WAIVED,
            ControlEvaluationStatus.MET,
            True,
            False,
        ),
        # NOT_APPLICABLE shares rank with PARTIAL — moving between them is
        # neither improvement nor regression.
        (
            ControlEvaluationStatus.NOT_APPLICABLE,
            ControlEvaluationStatus.PARTIAL,
            False,
            False,
        ),
    ],
)
def test_improvement_and_regression_match_rank_table(
    before: ControlEvaluationStatus,
    after: ControlEvaluationStatus,
    improved: bool,
    regressed: bool,
) -> None:
    assert _is_improvement(before, after) is improved
    assert _is_regression(before, after) is regressed


def test_improvement_regression_handle_none_inputs() -> None:
    # Added/removed controls (None on one side) are never classified as
    # "improved" or "regressed" — they show up under added/removed instead.
    assert _is_improvement(None, ControlEvaluationStatus.MET) is False
    assert _is_regression(ControlEvaluationStatus.MET, None) is False
    assert _is_improvement(None, None) is False
    assert _is_regression(None, None) is False


# ---------------------------------------------------------------------------
# ControlDelta.category
# ---------------------------------------------------------------------------


def test_control_delta_category_for_added_removed_changed_unchanged() -> None:
    added = ControlDelta(control_id="X", before=None, after=ControlEvaluationStatus.MET)
    removed = ControlDelta(control_id="X", before=ControlEvaluationStatus.MET, after=None)
    unchanged = ControlDelta(
        control_id="X",
        before=ControlEvaluationStatus.MET,
        after=ControlEvaluationStatus.MET,
    )
    changed = ControlDelta(
        control_id="X",
        before=ControlEvaluationStatus.MISSING,
        after=ControlEvaluationStatus.MET,
    )
    assert added.category == "added"
    assert removed.category == "removed"
    assert unchanged.category == "unchanged"
    assert changed.category == "changed"


# ---------------------------------------------------------------------------
# compare_bundles + BundleComparison.to_dict — full output contract.
# ---------------------------------------------------------------------------


def test_compare_bundles_full_diff_buckets_by_category() -> None:
    before = _make_bundle(
        "before-id",
        release_status=ReleaseStatus.NOT_READY,
        coverage=40,
        confidence=70,
        evaluations=[
            _make_evaluation("KEEP", status=ControlEvaluationStatus.MET),
            _make_evaluation("UP", status=ControlEvaluationStatus.MISSING),
            _make_evaluation("DOWN", status=ControlEvaluationStatus.MET),
            _make_evaluation("GONE", status=ControlEvaluationStatus.MET),
        ],
    )
    after = _make_bundle(
        "after-id",
        release_status=ReleaseStatus.READY,
        coverage=85,
        confidence=92,
        evaluations=[
            _make_evaluation("KEEP", status=ControlEvaluationStatus.MET),
            _make_evaluation("UP", status=ControlEvaluationStatus.MET),
            _make_evaluation("DOWN", status=ControlEvaluationStatus.PARTIAL),
            _make_evaluation("NEW", status=ControlEvaluationStatus.WAIVED),
        ],
    )

    comparison = compare_bundles(before, after)

    assert isinstance(comparison, BundleComparison)
    assert comparison.before_id == "before-id"
    assert comparison.after_id == "after-id"
    assert comparison.before_release_status is ReleaseStatus.NOT_READY
    assert comparison.after_release_status is ReleaseStatus.READY
    assert comparison.coverage_delta == 45
    assert comparison.confidence_delta == 22

    payload = comparison.to_dict()
    assert payload["before_release_status"] == "not_ready"
    assert payload["after_release_status"] == "ready"
    assert payload["coverage_delta"] == 45

    controls = payload["controls"]
    assert isinstance(controls, dict)
    assert controls["added"] == ["NEW"]
    assert controls["removed"] == ["GONE"]
    assert controls["improved"] == ["UP"]
    assert controls["regressed"] == ["DOWN"]
    assert controls["unchanged"] == ["KEEP"]


def test_compare_bundles_zero_delta_when_inputs_identical() -> None:
    eval_set = [
        _make_evaluation("A", status=ControlEvaluationStatus.MET),
        _make_evaluation("B", status=ControlEvaluationStatus.MET),
    ]
    bundle = _make_bundle(
        "same",
        release_status=ReleaseStatus.READY,
        coverage=100,
        confidence=100,
        evaluations=eval_set,
    )
    comparison = compare_bundles(bundle, bundle)
    payload = comparison.to_dict()
    assert payload["coverage_delta"] == 0
    assert payload["confidence_delta"] == 0
    controls = payload["controls"]
    assert isinstance(controls, dict)
    assert controls["unchanged"] == ["A", "B"]
    assert controls["added"] == []
    assert controls["removed"] == []
    assert controls["improved"] == []
    assert controls["regressed"] == []


# ---------------------------------------------------------------------------
# load_bundle — round-trip through JSON.
# ---------------------------------------------------------------------------


def test_load_bundle_round_trips_json(tmp_path: Path) -> None:
    bundle = _make_bundle(
        "round-trip",
        release_status=ReleaseStatus.CONDITIONAL,
        coverage=60,
        confidence=80,
        evaluations=[_make_evaluation("X", status=ControlEvaluationStatus.PARTIAL)],
    )
    payload = bundle.model_dump(mode="json")
    target = tmp_path / "bundle.json"
    target.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_bundle(target)
    assert loaded.bundle_id == "round-trip"
    assert loaded.summary.release_status is ReleaseStatus.CONDITIONAL
    assert loaded.control_evaluations[0].evaluation_status is (ControlEvaluationStatus.PARTIAL)
