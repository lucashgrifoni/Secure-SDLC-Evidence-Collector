"""Markdown report exporter."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from evidence_collector.domain.enums import ControlCriticality, ReleaseStatus
from evidence_collector.domain.models import ControlEvaluation, EvidenceBundle, Gap, Summary
from evidence_collector.exporters._atomic import write_atomic
from evidence_collector.exporters._jinja import get_environment
from evidence_collector.scoring.risk import risk_weighted_status

# The same words and sentences summary.html shows for each verdict, so the two
# human-facing reports never describe one release in different terms.
VERDICT_WORDS: dict[ReleaseStatus, str] = {
    ReleaseStatus.READY: "Ready",
    ReleaseStatus.CONDITIONAL: "Conditional",
    ReleaseStatus.NOT_READY: "Not ready",
}
VERDICT_MEANINGS: dict[ReleaseStatus, str] = {
    ReleaseStatus.READY: "Every control is met, waived or not applicable.",
    ReleaseStatus.CONDITIONAL: (
        "No critical control lacks required evidence, but at least one control is "
        "partial or missing, or supplied evidence was set aside."
    ),
    ReleaseStatus.NOT_READY: "A critical control lacks required evidence.",
}
RISK_SET_VERDICT = "The risk-weighted rule set this verdict. The next line says what it found."

_CRITICALITY_ORDER = (
    ControlCriticality.CRITICAL,
    ControlCriticality.HIGH,
    ControlCriticality.MEDIUM,
    ControlCriticality.LOW,
)


def most_critical_first[Ranked: (Gap, ControlEvaluation)](items: Iterable[Ranked]) -> list[Ranked]:
    """Order items critical, high, medium, low; equal ranks keep the bundle order."""
    return sorted(items, key=lambda item: _CRITICALITY_ORDER.index(item.criticality))


def verdict_meaning(summary: Summary) -> str:
    """Explain the verdict, naming the risk-weighted rule when it moved the verdict.

    The presence-based sentences describe gaps; after a KEV or high-EPSS
    downgrade there may be no gap behind the verdict at all. The final status
    can also be lowered later by the release-anchor drift check, so "moved" is
    read from the risk assessment itself, as summary.html does.
    """
    risk = summary.risk_assessment
    if risk is not None and risk_weighted_status(risk) != risk.base_release_status:
        return RISK_SET_VERDICT
    return VERDICT_MEANINGS[summary.release_status]


def bundle_to_markdown(bundle: EvidenceBundle) -> str:
    env = get_environment()
    template = env.get_template("report.md.j2")
    return template.render(
        bundle=bundle,
        verdict_word=VERDICT_WORDS[bundle.summary.release_status],
        verdict_meaning=verdict_meaning(bundle.summary),
        gaps=most_critical_first(bundle.gaps),
        controls=most_critical_first(bundle.control_evaluations),
        control_names={c.control_id: c.control_name for c in bundle.control_evaluations},
    )


def export_markdown(bundle: EvidenceBundle, output_path: str | Path) -> Path:
    return write_atomic(Path(output_path).expanduser(), bundle_to_markdown(bundle))
