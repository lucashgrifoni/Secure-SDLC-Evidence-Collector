"""Enrichment pipeline: EPSS + KEV → VulnerabilityIntelligence.

Given a loaded :class:`EvidenceBundle`, walk every :class:`NormalizedEvidence`
that carries ``cve_ids`` and attach a :class:`VulnerabilityIntelligence`
summary using the feeds in :mod:`evidence_collector.intelligence.epss`
and :mod:`evidence_collector.intelligence.kev`. Pure function; no network.

Network refresh (downloading current EPSS + KEV feeds) is intentionally
kept out of this module so the enrichment step can be unit-tested with
synthetic feeds and so air-gapped environments can supply their own
files via the ``--epss-feed`` and ``--kev-feed`` CLI flags.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from evidence_collector.domain.models import (
    EvidenceBundle,
    NormalizedEvidence,
    TopRiskCve,
    VulnerabilityIntelligence,
)
from evidence_collector.intelligence.epss import EpssFeed
from evidence_collector.intelligence.kev import KevFeed

DEFAULT_TOP_RISK_LIMIT = 5


@dataclass(frozen=True)
class EnrichmentReport:
    """Side-effect-free summary of what changed when ``enrich_bundle`` ran.

    Useful for CI logging and for the JSON-logs surface; the bundle
    itself already carries the per-evidence detail under
    ``evidence[*].vulnerability_intelligence``.
    """

    evidence_enriched: int
    evidence_with_cves: int
    distinct_cves: int
    cves_in_kev: int
    epss_feed_date: str | None
    kev_feed_date: str | None


def enrich_evidence(
    evidence: NormalizedEvidence,
    epss: EpssFeed,
    kev: KevFeed,
    *,
    top_risk_limit: int = DEFAULT_TOP_RISK_LIMIT,
    now: datetime | None = None,
) -> NormalizedEvidence:
    """Return a copy of ``evidence`` with ``vulnerability_intelligence`` set.

    When the evidence has no CVE IDs the returned record is byte-equal to
    the input (the optional field stays ``None``). This is a no-op for
    evidence types that do not carry CVE data (``test_result``,
    ``code_review``, ``threat_model``, etc).
    """
    if not evidence.cve_ids:
        return evidence

    cve_ids_upper = [cid.upper() for cid in evidence.cve_ids]
    seen: set[str] = set()
    deduped: list[str] = []
    for cid in cve_ids_upper:
        if cid not in seen and cid.startswith("CVE-"):
            seen.add(cid)
            deduped.append(cid)

    epss_lookup = [(cid, epss.get(cid)) for cid in deduped]
    kev_lookup = [(cid, kev.get(cid)) for cid in deduped]

    epss_known = [(cid, record) for cid, record in epss_lookup if record is not None]
    in_kev_count = sum(1 for _, rec in kev_lookup if rec is not None)
    ransomware_count = sum(
        1 for _, rec in kev_lookup if rec is not None and rec.known_ransomware_use
    )

    max_epss_score = max(rec.epss_score for _, rec in epss_known) if epss_known else None
    max_epss_percentile = max(rec.epss_percentile for _, rec in epss_known) if epss_known else None

    kev_by_cve = {cid: rec for cid, rec in kev_lookup if rec is not None}
    ranked = sorted(
        epss_known,
        key=lambda pair: pair[1].epss_percentile,
        reverse=True,
    )
    top_risk: list[TopRiskCve] = []
    for cid, rec in ranked[:top_risk_limit]:
        kev_rec = kev_by_cve.get(cid)
        top_risk.append(
            TopRiskCve(
                cve_id=cid,
                epss_score=rec.epss_score,
                epss_percentile=rec.epss_percentile,
                in_kev=kev_rec is not None,
                known_ransomware=kev_rec.known_ransomware_use if kev_rec else False,
            )
        )

    intel = VulnerabilityIntelligence(
        cve_count=len(deduped),
        max_epss_score=max_epss_score,
        max_epss_percentile=max_epss_percentile,
        cves_in_kev_count=in_kev_count,
        cves_known_ransomware_count=ransomware_count,
        top_risk_cves=top_risk,
        epss_feed_date=epss.feed_date,
        epss_model_version=epss.model_version,
        kev_feed_date=kev.feed_date,
        enriched_at=now or datetime.now(tz=UTC),
    )
    return evidence.model_copy(update={"vulnerability_intelligence": intel})


def enrich_bundle(
    bundle: EvidenceBundle,
    epss: EpssFeed,
    kev: KevFeed,
    *,
    top_risk_limit: int = DEFAULT_TOP_RISK_LIMIT,
    now: datetime | None = None,
) -> tuple[EvidenceBundle, EnrichmentReport]:
    """Return an enriched copy of ``bundle`` plus a summary report.

    The function never mutates the input bundle; consumers that want
    the in-memory bundle replaced should reassign the return value.
    """
    fixed_now = now or datetime.now(tz=UTC)
    enriched_evidence = [
        enrich_evidence(e, epss, kev, top_risk_limit=top_risk_limit, now=fixed_now)
        for e in bundle.evidence
    ]
    enriched_bundle = bundle.model_copy(update={"evidence": enriched_evidence})

    distinct: set[str] = set()
    with_cves = 0
    in_kev = 0
    for evidence in enriched_evidence:
        if not evidence.cve_ids:
            continue
        with_cves += 1
        for cid in evidence.cve_ids:
            distinct.add(cid.upper())
        if evidence.vulnerability_intelligence is not None:
            in_kev += evidence.vulnerability_intelligence.cves_in_kev_count

    report = EnrichmentReport(
        evidence_enriched=sum(
            1 for e in enriched_evidence if e.vulnerability_intelligence is not None
        ),
        evidence_with_cves=with_cves,
        distinct_cves=len(distinct),
        cves_in_kev=in_kev,
        epss_feed_date=epss.feed_date,
        kev_feed_date=kev.feed_date,
    )
    return enriched_bundle, report
