"""Vulnerability-intelligence enrichment for the evidence bundle.

Pure-Python module with two responsibilities:

* fetch and cache the public EPSS (FIRST.org) and CISA KEV feeds; and
* enrich a :class:`evidence_collector.domain.models.EvidenceBundle` with
  per-evidence EPSS/KEV summaries based on the CVE IDs collected by the
  parsers.

This package is intentionally optional: the collector keeps working
without ever calling :func:`enrich_bundle`, and the bundle stays
schema-compatible with consumers that never asked for enrichment.
"""

from evidence_collector.intelligence.enricher import (
    EnrichmentReport,
    enrich_bundle,
    enrich_evidence,
)
from evidence_collector.intelligence.epss import EpssFeed, EpssRecord, load_epss_feed
from evidence_collector.intelligence.kev import KevFeed, KevRecord, load_kev_feed

__all__ = [
    "EnrichmentReport",
    "EpssFeed",
    "EpssRecord",
    "KevFeed",
    "KevRecord",
    "enrich_bundle",
    "enrich_evidence",
    "load_epss_feed",
    "load_kev_feed",
]
