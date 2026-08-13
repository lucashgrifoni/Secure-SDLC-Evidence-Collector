"""``sdlc-evidence enrich`` — attach EPSS + CISA KEV intelligence to a bundle.

Given an existing ``bundle.json``, walk every evidence record that
carries ``cve_ids`` and attach a :class:`VulnerabilityIntelligence`
summary computed from local EPSS + KEV feeds. The command is offline by
default: the user supplies feed paths via ``--epss-feed`` and
``--kev-feed``. Network refresh stays out of this CLI surface so the
collector remains side-effect-free and air-gap-friendly.

Exit codes:

* 0 — enrichment ran (with or without matches); bundle written to ``--output``.
* 3 — bundle path missing or malformed, or a feed path was supplied but the
  file is unreadable / malformed. See ``cli/_exit_codes.EXIT_INPUT_ERROR``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_atomic
from evidence_collector.intelligence import (
    EpssFeed,
    KevFeed,
    enrich_bundle,
    load_epss_feed,
    load_kev_feed,
)


def register(app: typer.Typer) -> None:
    """Attach the ``enrich`` command to ``app``."""

    @app.command("enrich")
    def cmd_enrich(
        bundle_path: Annotated[
            Path,
            typer.Argument(
                # No exists=True: Click validates it BEFORE the command body and
                # raises UsageError -> exit 2, the not_ready code. The body below
                # already catches OSError and exits EXIT_INPUT_ERROR, which is what
                # the README promises for every input failure.
                file_okay=True,
                dir_okay=False,
                readable=True,
                help="Path to the bundle.json to enrich.",
            ),
        ],
        output: Annotated[
            Path | None,
            typer.Option(
                "--output",
                "-o",
                help=(
                    "Where to write the enriched bundle. When omitted, the "
                    "command overwrites BUNDLE_PATH in place."
                ),
            ),
        ] = None,
        epss_feed: Annotated[
            Path | None,
            typer.Option(
                "--epss-feed",
                help=(
                    "Local EPSS feed file (CSV or .csv.gz). Without this flag "
                    "the enrichment runs with an empty EPSS feed (KEV-only). "
                    "Download from https://epss.cyentia.com/."
                ),
            ),
        ] = None,
        kev_feed: Annotated[
            Path | None,
            typer.Option(
                "--kev-feed",
                help=(
                    "Local CISA KEV catalog JSON. Without this flag the "
                    "enrichment runs with an empty KEV catalog (EPSS-only). "
                    "Download from https://www.cisa.gov/sites/default/files/"
                    "feeds/known_exploited_vulnerabilities.json."
                ),
            ),
        ] = None,
        top_risk_limit: Annotated[
            int,
            typer.Option(
                "--top-risk-limit",
                min=0,
                max=50,
                help="How many CVEs to list per evidence in the top-risk summary.",
            ),
        ] = 5,
    ) -> None:
        """Attach EPSS + CISA KEV intelligence to a bundle.json."""
        bundle = _load_bundle(bundle_path)
        # A feed that was asked for but could not be used must fail loudly.
        # The loaders degrade an unreadable feed into an empty one so the
        # library never raises; at the CLI boundary that would be
        # indistinguishable from "no feed supplied", and the resulting bundle
        # would claim "no exploitable CVEs" without ever reading a feed.
        epss = (
            _require_usable(load_epss_feed(epss_feed), epss_feed, "EPSS")
            if epss_feed
            else EpssFeed(feed_date=None)
        )
        kev = (
            _require_usable(load_kev_feed(kev_feed), kev_feed, "CISA KEV")
            if kev_feed
            else KevFeed(feed_date=None)
        )

        enriched, report = enrich_bundle(bundle, epss, kev, top_risk_limit=top_risk_limit)
        destination = output or bundle_path
        write_atomic(destination, enriched.model_dump_json(indent=2, exclude_none=False))

        if is_json_logs():
            emit_event(
                "enrich_completed",
                bundle=str(destination),
                evidence_enriched=report.evidence_enriched,
                evidence_with_cves=report.evidence_with_cves,
                distinct_cves=report.distinct_cves,
                cves_in_kev=report.cves_in_kev,
                epss_feed_date=report.epss_feed_date,
                kev_feed_date=report.kev_feed_date,
            )
        else:
            console.print(
                "[green]enriched[/green] "
                f"evidence={report.evidence_enriched}/{report.evidence_with_cves} "
                f"cves={report.distinct_cves} kev={report.cves_in_kev} "
                f"feeds: epss={report.epss_feed_date or 'absent'} "
                f"kev={report.kev_feed_date or 'absent'}"
            )
            console.print(f"bundle.json → {destination}")


def _require_usable[FeedT: (EpssFeed, KevFeed)](feed: FeedT, path: Path, label: str) -> FeedT:
    """Return ``feed`` when it actually carries records, else exit EXIT_INPUT_ERROR.

    ``load_epss_feed`` / ``load_kev_feed`` deliberately degrade a missing or
    malformed file into an empty feed so library callers keep working. At the
    CLI boundary that degradation is dangerous: an empty feed produces exactly
    the same bundle as passing no feed at all, so a typo in the path silently
    turns an exploitability check into a no-op. Requesting a feed is a promise
    that it was consulted; if it could not be, say so and stop.
    """
    if feed.records:
        return feed
    if not path.is_file():
        reason = "file not found"
    else:
        reason = "no usable records (unreadable, empty, or malformed)"
    if is_json_logs():
        emit_event("enrich_failed", feed=str(path), feed_kind=label, reason=reason)
    else:
        console.print(f"[red]{label} feed {path} could not be used:[/red] {reason}")
    raise typer.Exit(code=EXIT_INPUT_ERROR)


def _load_bundle(path: Path) -> EvidenceBundle:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if is_json_logs():
            emit_event("enrich_failed", bundle=str(path), reason=str(exc))
        else:
            console.print(f"[red]Could not read {path}:[/red] {exc}")
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
    try:
        return EvidenceBundle.model_validate(raw)
    except ValidationError as exc:
        if is_json_logs():
            emit_event("enrich_failed", bundle=str(path), reason=str(exc))
        else:
            console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
