"""Risk-weighted release verdict (T6.6, opt-in).

The default presence-based verdict (in ``scoring.engine``) blocks
releases on missing required evidence. That captures hygiene but is
blind to whether the actually-present vulnerabilities are exploitable.

When the run is invoked with ``--risk-mode epss-weighted`` the
``apply_risk_mode`` function in this module re-derives the verdict
using the EPSS / KEV signal already embedded in evidence via
``--enrich``:

* a CVE in CISA KEV with ``known_ransomware`` ⇒ release is forced to
  ``not_ready`` regardless of the base verdict
* any CVE in KEV (without ransomware) ⇒ release is at least
  ``conditional``
* any CVE with EPSS percentile ≥ ``epss_percentile_threshold`` ⇒
  release is at least ``conditional``
* otherwise the base verdict from ``scoring.engine`` is kept as-is

Reachability is **honoured**: a CVE on evidence with
``reachability.status == "not_reachable"`` is treated as
"not exploitable in this product" and excluded from the count even
if EPSS / KEV would otherwise flag it. ``reachability.status ==
"unknown"`` is treated as "could be exploitable" (conservative).

This module never mutates the input summary; it returns a new
``Summary`` with the risk-weighted ``release_status`` and a
``risk_assessment`` block carrying the rationale.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import (
    NormalizedEvidence,
    RiskAssessment,
    Summary,
)

DEFAULT_EPSS_PERCENTILE_THRESHOLD = 0.7


class RiskMode(StrEnum):
    """Verdict mode selected by ``--risk-mode``."""

    OFF = "off"
    EPSS_WEIGHTED = "epss-weighted"


@dataclass(frozen=True)
class RiskThresholds:
    """Configurable thresholds for the EPSS-weighted verdict."""

    epss_percentile_threshold: float = DEFAULT_EPSS_PERCENTILE_THRESHOLD
    kev_blocks: bool = True


_STATUS_RANK: dict[ReleaseStatus, int] = {
    ReleaseStatus.READY: 0,
    ReleaseStatus.CONDITIONAL: 1,
    ReleaseStatus.NOT_READY: 2,
}


def _worse(a: ReleaseStatus, b: ReleaseStatus) -> ReleaseStatus:
    """Return whichever status is worse (further from ``ready``)."""
    return a if _STATUS_RANK[a] >= _STATUS_RANK[b] else b


def _reachability_blocks_signal(evidence: NormalizedEvidence) -> bool:
    """Return ``True`` when evidence reachability disqualifies its CVEs from risk weighting.

    Only ``not_reachable`` actively suppresses the signal. ``unknown``
    and ``reachable`` keep the CVEs in play; reachable is the
    canonical "exploitable in this code base" verdict.
    """
    reach = evidence.reachability
    return reach is not None and reach.status == "not_reachable"


def _count_exploitable(
    evidence_list: Sequence[NormalizedEvidence],
    thresholds: RiskThresholds,
) -> dict[str, int]:
    """Count exploitable CVEs across enriched evidence.

    Returns counters for total exploitable, KEV, KEV-with-ransomware,
    and high-EPSS. Each CVE is counted once per occurrence in the
    bundle's enrichment data, not deduplicated globally — the goal is
    "how many independent signals say something is exploitable?" not
    "how many distinct CVEs are exploitable?".
    """
    counters = {
        "exploitable": 0,
        "kev": 0,
        "kev_ransomware": 0,
        "high_epss": 0,
    }
    for evidence in evidence_list:
        if _reachability_blocks_signal(evidence):
            continue
        intel = evidence.vulnerability_intelligence
        if intel is None:
            continue
        for top in intel.top_risk_cves:
            is_kev = top.in_kev
            is_kev_ransomware = is_kev and top.known_ransomware
            is_high_epss = top.epss_percentile >= thresholds.epss_percentile_threshold
            if is_kev or is_high_epss:
                counters["exploitable"] += 1
            if is_kev:
                counters["kev"] += 1
            if is_kev_ransomware:
                counters["kev_ransomware"] += 1
            if is_high_epss:
                counters["high_epss"] += 1
    return counters


def _decide_risk_weighted_status(
    base: ReleaseStatus,
    counters: dict[str, int],
    thresholds: RiskThresholds,
) -> tuple[ReleaseStatus, str]:
    """Return ``(new_status, rationale)`` for the risk-weighted verdict.

    The rationale is a short human-readable explanation that travels
    inside ``RiskAssessment.rationale``. Auditors read this string;
    keep it precise.
    """
    if counters["kev_ransomware"] > 0 and thresholds.kev_blocks:
        return ReleaseStatus.NOT_READY, (
            f"{counters['kev_ransomware']} CVE(s) in CISA KEV with known "
            "ransomware use; release blocked under epss-weighted mode."
        )
    if counters["exploitable"] > 0:
        new_status = _worse(base, ReleaseStatus.CONDITIONAL)
        return new_status, (
            f"{counters['exploitable']} exploitable CVE(s) "
            f"(KEV={counters['kev']}, EPSS>={thresholds.epss_percentile_threshold:.2f}: "
            f"{counters['high_epss']}); release downgraded to "
            f"{new_status.value}."
        )
    return base, (
        "No exploitable CVEs detected under the EPSS / KEV thresholds; "
        "presence-based verdict preserved."
    )


def apply_risk_mode(
    summary: Summary,
    evidence_list: Sequence[NormalizedEvidence],
    *,
    mode: RiskMode = RiskMode.OFF,
    thresholds: RiskThresholds | None = None,
) -> Summary:
    """Return a new ``Summary`` with the risk-weighted verdict applied.

    When ``mode == RiskMode.OFF`` the input ``Summary`` is returned
    unchanged. When ``mode == RiskMode.EPSS_WEIGHTED`` the verdict is
    re-derived from EPSS / KEV signals and a ``RiskAssessment`` block
    is attached so the rationale is auditable.
    """
    if mode == RiskMode.OFF:
        return summary

    thresholds = thresholds or RiskThresholds()
    counters = _count_exploitable(evidence_list, thresholds)
    new_status, rationale = _decide_risk_weighted_status(
        summary.release_status, counters, thresholds
    )
    assessment = RiskAssessment(
        mode=mode.value,
        epss_percentile_threshold=thresholds.epss_percentile_threshold,
        kev_blocks=thresholds.kev_blocks,
        exploitable_cve_count=counters["exploitable"],
        kev_cve_count=counters["kev"],
        kev_ransomware_cve_count=counters["kev_ransomware"],
        high_epss_cve_count=counters["high_epss"],
        base_release_status=summary.release_status,
        rationale=rationale,
    )
    return summary.model_copy(
        update={"release_status": new_status, "risk_assessment": assessment}
    )
