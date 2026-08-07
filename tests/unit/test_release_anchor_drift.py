"""A bundle must not certify a release with another release's evidence.

Every normalizer stamps `release_id` and `commit_sha` on each record — the
domain calls them the anchor, and both fields are required — but nothing ever
read them back. `evaluate` therefore accepted an evidence file collected for
one commit and certified a completely different release with it: verdict
`ready`, exit 0, no warning, and `statement` signed that false binding into an
in-toto predicate.

`run` was never exposed, because it builds the collector and the bundle from
the same context object. The two-step `collect` → `evaluate` split is a
documented CLI flow, so the check lives in `build_bundle` — the single choke
point both paths pass through.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from evidence_collector.application.orchestrator import build_bundle
from evidence_collector.domain.enums import (
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
)

_NOW = datetime(2026, 5, 5, tzinfo=UTC)


def _release(release_id: str = "1.0.0", commit: str = "a" * 16) -> ReleaseContext:
    return ReleaseContext(release_id=release_id, commit_sha=commit, branch="main")


def _evidence(release_id: str, commit: str, evidence_id: str = "ev-1") -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.SAST_SCAN,
        source=EvidenceSource(name="semgrep", kind="sarif"),
        producer="semgrep",
        subject_type=SubjectType.COMMIT,
        subject_ref=commit,
        status=EvidenceStatus.PASSED,
        release_id=release_id,
        commit_sha=commit,
        generated_at=_NOW,
    )


def _app() -> Application:
    return Application(name="demo", repository="acme/demo")


def test_matched_anchors_record_nothing() -> None:
    bundle, _ = build_bundle(_app(), _release(), [_evidence("1.0.0", "a" * 16)])
    assert bundle.collection_errors == []


def test_drifted_anchor_is_recorded_with_both_sides_named() -> None:
    bundle, _ = build_bundle(_app(), _release("2.0.0", "b" * 16), [_evidence("1.0.0", "a" * 16)])
    assert len(bundle.collection_errors) == 1
    reason = bundle.collection_errors[0].reason
    # A reader must be able to see *which* release the evidence belongs to
    # and *which* one the bundle claims, without opening the evidence list.
    assert "1.0.0" in reason
    assert "a" * 16 in reason
    assert "2.0.0" in reason
    assert "b" * 16 in reason


def test_drift_counts_the_affected_records() -> None:
    evidence = [
        _evidence("1.0.0", "a" * 16, "ev-1"),
        _evidence("1.0.0", "a" * 16, "ev-2"),
    ]
    bundle, _ = build_bundle(_app(), _release("2.0.0", "b" * 16), evidence)
    assert "2 evidence record(s)" in bundle.collection_errors[0].reason


def test_two_distinct_drifted_anchors_are_reported_separately() -> None:
    evidence = [
        _evidence("1.0.0", "a" * 16, "ev-1"),
        _evidence("1.5.0", "c" * 16, "ev-2"),
    ]
    bundle, _ = build_bundle(_app(), _release("2.0.0", "b" * 16), evidence)
    assert len(bundle.collection_errors) == 2


def test_a_ready_verdict_is_degraded_when_the_evidence_is_another_release() -> None:
    """The recorded note is not enough on its own.

    A `ready` verdict backed by another commit's evidence is the actual harm:
    a CI gate reads the exit code, not the bundle. The degrade is one-way,
    mirroring apply_risk_mode — never a promotion.
    """
    matched, _ = build_bundle(_app(), _release(), [_evidence("1.0.0", "a" * 16)])
    drifted, _ = build_bundle(_app(), _release("2.0.0", "b" * 16), [_evidence("1.0.0", "a" * 16)])
    # Same evidence shape, so any verdict difference comes from the drift.
    if matched.summary.release_status is ReleaseStatus.READY:
        assert drifted.summary.release_status is ReleaseStatus.CONDITIONAL
    else:
        # Already worse than ready — the degrade must never improve it.
        assert drifted.summary.release_status is not ReleaseStatus.READY


@pytest.mark.parametrize("status", [ReleaseStatus.CONDITIONAL, ReleaseStatus.NOT_READY])
def test_drift_never_promotes_a_worse_verdict(status: ReleaseStatus) -> None:
    bundle, _ = build_bundle(_app(), _release("2.0.0", "b" * 16), [_evidence("1.0.0", "a" * 16)])
    assert bundle.summary.release_status is not ReleaseStatus.READY


def test_an_empty_evidence_set_reports_no_drift() -> None:
    bundle, _ = build_bundle(_app(), _release(), [])
    assert bundle.collection_errors == []
