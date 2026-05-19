"""CISA Known Exploited Vulnerabilities (KEV) feed loader.

The KEV catalog is a JSON document maintained by CISA that lists CVEs
confirmed to be exploited in the wild. The schema is documented at
https://www.cisa.gov/known-exploited-vulnerabilities-catalog.

This module ships a deterministic loader that accepts either:

* a local file path (preferred for CI and air-gapped environments), or
* a freshly downloaded copy in a cache directory.

The loader never touches the network on its own. Network IO is centralised
in :func:`evidence_collector.intelligence.enricher._refresh_feeds` so the
default code path remains side-effect-free and unit-testable.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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
    except (json.JSONDecodeError, OSError):
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
