"""Bundle comparison use case.

Given two `EvidenceBundle` instances (or two JSON payloads), compute a
structured diff that highlights movement in coverage, confidence, release
status, and individual control evaluations.

The comparison is intentionally coarse — we surface *what changed*, not
every nested field — so the output is useful as a release-over-release
delta in CI comments and audit reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from evidence_collector.domain.enums import ControlEvaluationStatus, ReleaseStatus
from evidence_collector.domain.models import EvidenceBundle


@dataclass
class ControlDelta:
    control_id: str
    before: ControlEvaluationStatus | None
    after: ControlEvaluationStatus | None

    @property
    def category(self) -> str:
        if self.before is None:
            return "added"
        if self.after is None:
            return "removed"
        if self.before == self.after:
            return "unchanged"
        return "changed"


@dataclass
class BundleComparison:
    before_id: str
    after_id: str
    before_release_status: ReleaseStatus
    after_release_status: ReleaseStatus
    coverage_delta: int
    confidence_delta: int
    control_deltas: list[ControlDelta] = field(default_factory=list)
    before_epss_model_versions: list[str] = field(default_factory=list)
    after_epss_model_versions: list[str] = field(default_factory=list)

    @property
    def epss_model_drift(self) -> bool:
        """True when the two bundles were enriched by different EPSS models.

        EPSS scores are **not comparable across model versions** — v5
        (production 2026-06-15) re-fits the model rather than re-scoring
        under the old one, so a CVE's score can move without anything
        about the CVE or the release changing. A release-over-release
        diff that silently mixes two models invites exactly the wrong
        conclusion: "our exposure went up" when the model moved.

        Drift needs versions on *both* sides. One side empty means
        enrichment did not run there, which is an absence to notice
        separately, not a model change.
        """
        if not self.before_epss_model_versions or not self.after_epss_model_versions:
            return False
        return set(self.before_epss_model_versions) != set(self.after_epss_model_versions)

    def to_dict(self) -> dict[str, object]:
        return {
            "before_bundle_id": self.before_id,
            "after_bundle_id": self.after_id,
            "before_release_status": self.before_release_status.value,
            "after_release_status": self.after_release_status.value,
            "coverage_delta": self.coverage_delta,
            "confidence_delta": self.confidence_delta,
            "epss": {
                "before_model_versions": list(self.before_epss_model_versions),
                "after_model_versions": list(self.after_epss_model_versions),
                "model_drift": self.epss_model_drift,
            },
            "controls": {
                "added": [c.control_id for c in self.control_deltas if c.category == "added"],
                "removed": [c.control_id for c in self.control_deltas if c.category == "removed"],
                "improved": [
                    c.control_id
                    for c in self.control_deltas
                    if c.category == "changed" and _is_improvement(c.before, c.after)
                ],
                "regressed": [
                    c.control_id
                    for c in self.control_deltas
                    if c.category == "changed" and _is_regression(c.before, c.after)
                ],
                "unchanged": [
                    c.control_id for c in self.control_deltas if c.category == "unchanged"
                ],
            },
        }


_STATUS_RANK: dict[ControlEvaluationStatus, int] = {
    ControlEvaluationStatus.MET: 4,
    ControlEvaluationStatus.WAIVED: 3,
    ControlEvaluationStatus.PARTIAL: 2,
    ControlEvaluationStatus.NOT_APPLICABLE: 2,
    ControlEvaluationStatus.MISSING: 1,
}


def _is_improvement(
    before: ControlEvaluationStatus | None, after: ControlEvaluationStatus | None
) -> bool:
    if before is None or after is None:
        return False
    return _STATUS_RANK[after] > _STATUS_RANK[before]


def _is_regression(
    before: ControlEvaluationStatus | None, after: ControlEvaluationStatus | None
) -> bool:
    if before is None or after is None:
        return False
    return _STATUS_RANK[after] < _STATUS_RANK[before]


def _epss_model_versions(bundle: EvidenceBundle) -> list[str]:
    """Return the distinct EPSS model versions recorded on this bundle.

    More than one is possible and is not itself an error: a bundle can be
    enriched in stages. It is the difference *between* bundles that makes
    the scores incomparable.
    """
    return sorted(
        {
            evidence.vulnerability_intelligence.epss_model_version
            for evidence in bundle.evidence
            if evidence.vulnerability_intelligence
            and evidence.vulnerability_intelligence.epss_model_version
        }
    )


def compare_bundles(before: EvidenceBundle, after: EvidenceBundle) -> BundleComparison:
    before_by_id = {e.control_id: e.evaluation_status for e in before.control_evaluations}
    after_by_id = {e.control_id: e.evaluation_status for e in after.control_evaluations}
    all_ids = sorted(set(before_by_id) | set(after_by_id))
    deltas: list[ControlDelta] = [
        ControlDelta(
            control_id=control_id,
            before=before_by_id.get(control_id),
            after=after_by_id.get(control_id),
        )
        for control_id in all_ids
    ]
    return BundleComparison(
        before_id=before.bundle_id,
        after_id=after.bundle_id,
        before_release_status=before.summary.release_status,
        after_release_status=after.summary.release_status,
        coverage_delta=(
            after.summary.evidence_coverage_score - before.summary.evidence_coverage_score
        ),
        confidence_delta=(after.summary.confidence_score - before.summary.confidence_score),
        control_deltas=deltas,
        before_epss_model_versions=_epss_model_versions(before),
        after_epss_model_versions=_epss_model_versions(after),
    )


def load_bundle(path: str | Path) -> EvidenceBundle:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return EvidenceBundle.model_validate(data)
