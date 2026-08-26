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
from evidence_collector.controls import catalog_with_provenance
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


def _evidence_set(
    release_id: str, commit: str, *, kinds: list[EvidenceType]
) -> list[NormalizedEvidence]:
    """One passing record per evidence type in `kinds`, all sharing an anchor."""
    return [
        NormalizedEvidence(
            evidence_id=f"ev-{index}",
            evidence_type=kind,
            source=EvidenceSource(name="tool", kind="sarif"),
            producer="tool",
            subject_type=SubjectType.COMMIT,
            subject_ref=commit,
            status=EvidenceStatus.PASSED,
            release_id=release_id,
            commit_sha=commit,
            generated_at=_NOW,
        )
        for index, kind in enumerate(kinds)
    ]


def _catalog_types(*, recommended: bool) -> list[EvidenceType]:
    """Evidence types the shipped catalog asks for, read from the catalog.

    Derived rather than hardcoded so that a catalog change moves these tests
    with it instead of quietly turning the `ready` baseline below into a
    `conditional` one — which is the exact way the degrade assertion stopped
    running in the first place.
    """
    controls, _ = catalog_with_provenance(None)
    kinds: set[EvidenceType] = set()
    for control in controls:
        kinds.update(control.required_evidence_types or [])
        if recommended:
            kinds.update(control.recommended_evidence_types or [])
    return sorted(kinds, key=lambda kind: kind.value)


def test_a_ready_verdict_is_degraded_when_the_evidence_is_another_release() -> None:
    """The recorded note is not enough on its own.

    A `ready` verdict backed by another commit's evidence is the actual harm:
    a CI gate reads the exit code, not the bundle. The degrade is one-way,
    mirroring apply_risk_mode — never a promotion.

    The baseline has to genuinely reach `ready` or this proves nothing. It
    previously did not: the bundle was built from a single evidence record
    against a thirteen-control catalog, so it was always `not_ready`, the
    `if` never ran, and the one assertion that tests the degrade had never
    executed. The test passed on its `else` branch, which only restated that
    something already worse than `ready` was still not `ready`.
    """
    kinds = _catalog_types(recommended=True)
    matched, _ = build_bundle(_app(), _release(), _evidence_set("1.0.0", "a" * 16, kinds=kinds))
    assert matched.summary.release_status is ReleaseStatus.READY, (
        "baseline is not `ready`, so this test cannot observe a degrade; "
        f"got {matched.summary.release_status.value}"
    )

    drifted, _ = build_bundle(
        _app(), _release("2.0.0", "b" * 16), _evidence_set("1.0.0", "a" * 16, kinds=kinds)
    )
    assert drifted.summary.release_status is ReleaseStatus.CONDITIONAL


@pytest.mark.parametrize(
    ("recommended", "expected_baseline"),
    [
        (True, ReleaseStatus.READY),
        (False, ReleaseStatus.CONDITIONAL),
    ],
    ids=["from-ready", "from-conditional"],
)
def test_drift_never_promotes_a_verdict(
    recommended: bool, expected_baseline: ReleaseStatus
) -> None:
    """Each case starts from a different verdict, which is what makes it a case.

    The parameters were previously `CONDITIONAL` and `NOT_READY` and the body
    never referenced them, so pytest ran one identical assertion twice. Here
    the parameter selects the evidence set, the baseline is asserted, and the
    drifted verdict is checked against it.
    """
    kinds = _catalog_types(recommended=recommended)
    matched, _ = build_bundle(_app(), _release(), _evidence_set("1.0.0", "a" * 16, kinds=kinds))
    assert matched.summary.release_status is expected_baseline

    drifted, _ = build_bundle(
        _app(), _release("2.0.0", "b" * 16), _evidence_set("1.0.0", "a" * 16, kinds=kinds)
    )
    assert drifted.summary.release_status is not ReleaseStatus.READY
    if expected_baseline is not ReleaseStatus.READY:
        # Already below `ready`; the degrade must leave it exactly where it was.
        assert drifted.summary.release_status is expected_baseline


def test_an_empty_evidence_set_reports_no_drift() -> None:
    bundle, _ = build_bundle(_app(), _release(), [])
    assert bundle.collection_errors == []
