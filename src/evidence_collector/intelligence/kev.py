"""CISA Known Exploited Vulnerabilities (KEV) feed loader.

The KEV catalog is a JSON document maintained by CISA that lists CVEs
confirmed to be exploited in the wild. The schema is documented at
https://www.cisa.gov/known-exploited-vulnerabilities-catalog.

This module ships a deterministic loader that reads a local file path. The
operator supplies the catalog with ``enrich --kev-feed``; fetching it is their
job, which is what makes the command work in CI and air-gapped environments.

Nothing in this package touches the network — not the loader, not the
enricher. An earlier version of this docstring pointed at an
``enricher._refresh_feeds`` as the place network IO was centralised; no such
function exists, and the only outbound calls in the project are in the SCM
collectors and ``doctor``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.intelligence._feeds import MALFORMED_FEED

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class KevRecord:
    """A single CVE entry in the CISA KEV catalog."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    known_ransomware_use: bool


@dataclass
class KevFeed:
    """Loaded KEV catalog with O(1) CVE lookup."""

    feed_date: str | None
    records: dict[str, KevRecord] = field(default_factory=dict)

    def contains(self, cve_id: str) -> bool:
        return cve_id.upper() in self.records

    def get(self, cve_id: str) -> KevRecord | None:
        return self.records.get(cve_id.upper())


def _coerce_ransomware_flag(value: Any) -> bool:
    """KEV ships the ransomware flag as the string ``Known`` / ``Unknown``."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "known"
    return False


def _normalize_feed_date(value: Any) -> str | None:
    """Reduce KEV's ``dateReleased`` ISO timestamp to a YYYY-MM-DD string.

    The CISA feed publishes ``"2026-05-17T00:00:00.000Z"`` which exceeds
    the 20-char limit on :class:`VulnerabilityIntelligence.kev_feed_date`
    and is more granular than callers need (the consumer only cares
    which *day* the catalog was issued). Falls back to the raw string
    truncated to 20 chars if the value is not a parseable date.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # ISO 8601 starts with YYYY-MM-DD; trim aggressively.
    head = text[:10]
    if (
        len(head) == 10
        and head[4] == "-"
        and head[7] == "-"
        and head[:4].isdigit()
        and head[5:7].isdigit()
        and head[8:10].isdigit()
    ):
        return head
    return text[:20]


def load_kev_feed(path: Path) -> KevFeed:
    """Load a CISA KEV JSON catalog from ``path``.

    Returns an empty :class:`KevFeed` if the file is missing or malformed.
    The caller is expected to interpret an empty feed as "no enrichment
    possible" rather than as an error, so a network outage upstream
    degrades gracefully into the un-enriched baseline.
    """
    if not path.is_file():
        return KevFeed(feed_date=None, records={})
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    # The guard covered two of the ways a file can be malformed, and the
    # docstring above promises to tolerate all of them. A corrupted download
    # raised `UnicodeDecodeError`, `RecursionError` or a bare `ValueError`
    # straight past it and failed `enrich` outright. See `_feeds` for what
    # each member of the tuple stands for.
    except MALFORMED_FEED:
        logger.warning(
            "Could not read the KEV feed at %s; continuing without KEV enrichment.", path
        )
        return KevFeed(feed_date=None, records={})
    if not isinstance(raw, dict):
        return KevFeed(feed_date=None, records={})

    feed_date_value = raw.get("dateReleased") or raw.get("catalogVersion")
    feed_date = _normalize_feed_date(feed_date_value)

    records: dict[str, KevRecord] = {}
    vulnerabilities = raw.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return KevFeed(feed_date=feed_date, records={})

    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID")
        if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
            continue
        cve_id_upper = cve_id.upper()
        records[cve_id_upper] = KevRecord(
            cve_id=cve_id_upper,
            vendor_project=str(entry.get("vendorProject", "") or ""),
            product=str(entry.get("product", "") or ""),
            vulnerability_name=str(entry.get("vulnerabilityName", "") or ""),
            date_added=str(entry.get("dateAdded", "") or ""),
            known_ransomware_use=_coerce_ransomware_flag(entry.get("knownRansomwareCampaignUse")),
        )

    return KevFeed(feed_date=feed_date, records=records)
