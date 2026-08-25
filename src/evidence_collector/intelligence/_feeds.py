"""What "malformed feed" means to the intelligence loaders.

Both :func:`~evidence_collector.intelligence.epss.load_epss_feed` and
:func:`~evidence_collector.intelligence.kev.load_kev_feed` document the same
contract: a missing or malformed feed yields an empty feed, and the caller
reads that as "enrichment unavailable" and continues with the un-enriched
baseline. A corrupted download is an expected condition for these two, not an
error — the feeds are optional inputs fetched over the network, and the bundle
is complete without them.

Each loader had its own narrower guard, and a partly-downloaded file walked
straight past both. The failure modes below all reach the same conclusion —
*this file is not a usable feed* — so they are named once, here, next to the
contract they implement:

* ``OSError`` — unreadable file; also covers :class:`gzip.BadGzipFile`.
* ``EOFError`` — gzip stream cut off before its end-of-stream marker, which is
  what a truncated download actually looks like. Not an ``OSError``.
* ``ValueError`` — the widest of the five, and deliberately so: it covers
  :class:`json.JSONDecodeError`, :class:`UnicodeDecodeError` from a
  mis-encoded byte, and CPython's 4300-digit cap on converting a numeric
  literal to ``int``.
* ``RecursionError`` — JSON nested past the interpreter's stack limit.
* ``csv.Error`` — a CSV field over the 128 KiB module limit.

Catching ``ValueError`` around a whole parse body can also swallow a genuine
bug in our own parsing code. That is the accepted cost: the alternative is
that an optional enrichment step aborts a run over an input the docstring
already promised to tolerate. Both loaders log a warning naming the file
before degrading, so a swallowed defect leaves a trace rather than vanishing.
"""

from __future__ import annotations

import csv

MALFORMED_FEED: tuple[type[BaseException], ...] = (
    OSError,
    EOFError,
    ValueError,
    RecursionError,
    csv.Error,
)
