"""EPSS (Exploit Prediction Scoring System) feed loader.

The EPSS feed is published daily by FIRST.org as a gzipped CSV at
``https://epss.cyentia.com/epss_scores-current.csv.gz``. The header
comment line contains the model version and the score date, e.g.::

    #model_version:v2026.01.04,score_date:2026-05-17T00:00:00+0000
    cve,epss,percentile
    CVE-2023-1234,0.97132,0.99991
    ...

This module accepts either the gzipped CSV (auto-detected by file
suffix) or a plain ``.csv``. The loader is deterministic and never
touches the network; refresh is handled by
:mod:`evidence_collector.intelligence.enricher`.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from dataclasses import dataclass, field
from pathlib import Path

_HEADER_DATE_PATTERN = re.compile(r"score_date:([0-9]{4}-[0-9]{2}-[0-9]{2})")


@dataclass(frozen=True)
class EpssRecord:
    """A single CVE entry in the EPSS feed."""

    cve_id: str
    epss_score: float
    epss_percentile: float


@dataclass
class EpssFeed:
    """Loaded EPSS feed with O(1) CVE lookup."""

    feed_date: str | None
    records: dict[str, EpssRecord] = field(default_factory=dict)

    def get(self, cve_id: str) -> EpssRecord | None:
        return self.records.get(cve_id.upper())


def _open_csv(path: Path) -> io.TextIOWrapper | io.StringIO:
    """Open ``path`` for text reading, transparently gunzipping ``.gz``."""
    if path.suffix == ".gz":
        # gzip.open returns binary by default; wrap in TextIOWrapper.
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", newline="")
    raw_bytes = path.read_bytes()
    return io.StringIO(raw_bytes.decode("utf-8", errors="replace"))


def _parse_float(value: str) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    if result != result:  # NaN
        return None
    if result < 0.0 or result > 1.0:
        return None
    return result


def load_epss_feed(path: Path) -> EpssFeed:
    """Load an EPSS feed from ``path``.

    Returns an empty :class:`EpssFeed` if the file is missing, malformed,
    or contains no parseable rows. Callers treat an empty feed as
    "enrichment unavailable" so a stale or absent feed degrades into the
    pre-enrichment baseline rather than failing the pipeline.
    """
    if not path.is_file():
        return EpssFeed(feed_date=None, records={})

    feed_date: str | None = None
    records: dict[str, EpssRecord] = {}

    try:
        stream = _open_csv(path)
    except (OSError, gzip.BadGzipFile):
        return EpssFeed(feed_date=None, records={})

    with stream:
        first_line = stream.readline()
        if first_line.startswith("#"):
            match = _HEADER_DATE_PATTERN.search(first_line)
            if match:
                feed_date = match.group(1)
            header_line = stream.readline()
        else:
            header_line = first_line
        if not header_line:
            return EpssFeed(feed_date=feed_date, records={})

        reader = csv.DictReader(
            io.StringIO(header_line + stream.read()),
        )
        for row in reader:
            cve_id = (row.get("cve") or row.get("cveID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            score = _parse_float(row.get("epss", ""))
            percentile = _parse_float(row.get("percentile", ""))
            if score is None or percentile is None:
                continue
            records[cve_id] = EpssRecord(
                cve_id=cve_id,
                epss_score=score,
                epss_percentile=percentile,
            )

    return EpssFeed(feed_date=feed_date, records=records)
