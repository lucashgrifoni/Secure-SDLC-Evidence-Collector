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
    epss: EpssFeed | None,
    kev: KevFeed | None,
    *,
    top_risk_limit: int = DEFAULT_TOP_RISK_LIMIT,
    now: datetime | None = None,
) -> NormalizedEvidence:
    """Return a copy of ``evidence`` with ``vulnerability_intelligence`` set.

    When the evidence has no CVE IDs the returned record is byte-equal to
    the input (the optional field stays ``None``). This is a no-op for
    evidence types that do not carry CVE data (``test_result``,
    ``code_review``, ``threat_model``, etc).

    ``None`` for a feed means that source was not supplied. An absent source
    is not a clean result: its fields are carried over from the record's
    prior intelligence (KEV counts and flags when there is no KEV feed, EPSS
    scores and the EPSS-ranked top list when there is no EPSS feed), or, on a
    first enrichment, marked ``kev_consulted`` / ``epss_consulted`` = False.
    With neither feed the record is returned unchanged.
    """
    if not evidence.cve_ids or (epss is None and kev is None):
        return evidence

    cve_ids_upper = [cid.upper() for cid in evidence.cve_ids]
    seen: set[str] = set()
    deduped: list[str] = []
    for cid in cve_ids_upper:
        if cid not in seen and cid.startswith("CVE-"):
            seen.add(cid)
            deduped.append(cid)

    prior = evidence.vulnerability_intelligence

    if kev is not None:
        kev_ids = {cid for cid in deduped if kev.get(cid) is not None}
        ransomware_ids = {
            cid for cid in kev_ids if (rec := kev.get(cid)) is not None and rec.known_ransomware_use
        }
        in_kev_count = len(kev_ids)
        ransomware_count = len(ransomware_ids)
        kev_feed_date = kev.feed_date
        kev_consulted = True
    else:
        # No KEV feed: carry forward what an earlier enrichment recorded. The
        # identities live in kev_cve_ids; bundles enriched before that field
        # existed only marked KEV CVEs inside the top list, so those count too.
        prior_top = prior.top_risk_cves if prior else []
        kev_ids = set(prior.kev_cve_ids if prior else []) | {
            top.cve_id for top in prior_top if top.in_kev
        }
        ransomware_ids = set(prior.kev_ransomware_cve_ids if prior else []) | {
            top.cve_id for top in prior_top if top.in_kev and top.known_ransomware
        }
        in_kev_count = max(len(kev_ids), prior.cves_in_kev_count if prior else 0)
        ransomware_count = max(
            len(ransomware_ids), prior.cves_known_ransomware_count if prior else 0
        )
        kev_feed_date = prior.kev_feed_date if prior else None
        kev_consulted = prior.kev_consulted if prior else False

    def kev_flags(cid: str) -> tuple[bool, bool]:
        return cid in kev_ids, cid in ransomware_ids

    if epss is not None:
        epss_known = [(cid, epss_rec) for cid in deduped if (epss_rec := epss.get(cid)) is not None]
        max_epss_score = max(rec.epss_score for _, rec in epss_known) if epss_known else None
        max_epss_percentile = (
            max(rec.epss_percentile for _, rec in epss_known) if epss_known else None
        )
        ranked = sorted(epss_known, key=lambda pair: pair[1].epss_percentile, reverse=True)
        scored = [
            (cid, rec.epss_score, rec.epss_percentile) for cid, rec in ranked[:top_risk_limit]
        ]
        epss_feed_date = epss.feed_date
        epss_model_version = epss.model_version
        epss_consulted = True
    else:
        # No EPSS feed: keep the earlier scores and ranking, refresh KEV flags.
        scored = [
            (top.cve_id, top.epss_score, top.epss_percentile)
            for top in (prior.top_risk_cves if prior else [])
        ][:top_risk_limit]
        max_epss_score = prior.max_epss_score if prior else None
        max_epss_percentile = prior.max_epss_percentile if prior else None
        epss_feed_date = prior.epss_feed_date if prior else None
        epss_model_version = prior.epss_model_version if prior else None
        epss_consulted = prior.epss_consulted if prior else False

    top_risk = [
        TopRiskCve(
            cve_id=cid,
            epss_score=score,
            epss_percentile=percentile,
            in_kev=kev_flags(cid)[0],
            known_ransomware=kev_flags(cid)[1],
        )
        for cid, score, percentile in scored
    ]

    intel = VulnerabilityIntelligence(
        cve_count=len(deduped),
        max_epss_score=max_epss_score,
        max_epss_percentile=max_epss_percentile,
        cves_in_kev_count=in_kev_count,
        cves_known_ransomware_count=ransomware_count,
        top_risk_cves=top_risk,
        epss_feed_date=epss_feed_date,
        epss_model_version=epss_model_version,
        kev_feed_date=kev_feed_date,
        kev_cve_ids=sorted(kev_ids),
        kev_ransomware_cve_ids=sorted(ransomware_ids),
        epss_consulted=epss_consulted,
        kev_consulted=kev_consulted,
        enriched_at=now or datetime.now(tz=UTC),
    )
    return evidence.model_copy(update={"vulnerability_intelligence": intel})


def enrich_bundle(
    bundle: EvidenceBundle,
    epss: EpssFeed | None,
    kev: KevFeed | None,
    *,
    top_risk_limit: int = DEFAULT_TOP_RISK_LIMIT,
    now: datetime | None = None,
) -> tuple[EvidenceBundle, EnrichmentReport]:
    """Return an enriched copy of ``bundle`` plus a summary report.

    The function never mutates the input bundle; consumers that want
    the in-memory bundle replaced should reassign the return value.
    ``None`` for a feed means it was not supplied; see :func:`enrich_evidence`.
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
        epss_feed_date=epss.feed_date if epss else None,
        kev_feed_date=kev.feed_date if kev else None,
    )
    return enriched_bundle, report
