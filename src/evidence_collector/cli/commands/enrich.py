"""``sdlc-evidence enrich`` — attach EPSS + CISA KEV intelligence to a bundle.

Given an existing ``bundle.json``, walk every evidence record that
carries ``cve_ids`` and attach a :class:`VulnerabilityIntelligence`
summary computed from local EPSS + KEV feeds. The command is offline by
default: the user supplies feed paths via ``--epss-feed`` and
``--kev-feed``. Network refresh stays out of this CLI surface so the
collector remains side-effect-free and air-gap-friendly.

When the bundle was built with ``--risk-mode epss-weighted`` (it carries a
``summary.risk_assessment``), the verdict is re-derived under that recorded
mode and threshold once the intelligence is attached. A bundle built in the
default mode keeps its verdict and summary unchanged. For a bundle built with
``--profile cra-2026``, each record's ``metadata.cra.global_exploitation_signal``
is recomputed from the new intelligence.

When the verdict or risk assessment changes, ``report.md`` and ``summary.html``
are re-rendered and written with the bundle as one set: next to the bundle when
writing in place, or next to ``--output`` for each report the input directory
had. Otherwise the reports are not touched.

With neither ``--epss-feed`` nor ``--kev-feed`` there is no source to consult:
the bundle is left unchanged (copied to ``--output`` when given), a warning is
printed, and the prior intelligence and verdict are kept.

Exit codes:

* 0 — enrichment ran (with or without matches), or was skipped because no
  feed was supplied; bundle written to ``--output``.
  The exit code does not reflect ``release_status``; gate on the bundle.
* 3 — bundle path missing or malformed (including an unknown recorded risk
  mode), or a feed path was supplied but the file is unreadable / malformed.
  See ``cli/_exit_codes.EXIT_INPUT_ERROR``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.markup import escape

from evidence_collector.application.orchestrator import rederive_risk_verdict
from evidence_collector.application.profiles import refresh_cra_exploitation_signals
from evidence_collector.cli._errors import report_error
from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR, UNREADABLE_INPUT
from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_all_or_nothing, write_atomic
from evidence_collector.exporters.html import bundle_to_html
from evidence_collector.exporters.markdown import bundle_to_markdown
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
                    "the enrichment runs with an empty EPSS feed (KEV-only); with "
                    "neither feed the bundle is left unchanged. "
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
                    "enrichment runs with an empty KEV catalog (EPSS-only); with "
                    "neither feed the bundle is left unchanged. "
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
        destination = output or bundle_path
        if epss_feed is None and kev_feed is None:
            # No source to consult. Enriching with two empty feeds would replace
            # every CVE's intelligence with nothing and re-derive the verdict as
            # if a clean assessment had been made: a not_ready KEV-ransomware
            # bundle came back at its presence-based status. Keep it as it is.
            report_error(
                f"enrich: no feed supplied (--epss-feed / --kev-feed); {bundle_path} "
                "left unchanged, prior intelligence and verdict kept",
                event="enrich_skipped",
                bundle=str(destination),
            )
            if destination != bundle_path:
                write_atomic(destination, bundle_path.read_text(encoding="utf-8-sig"))
            return
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
        try:
            enriched = rederive_risk_verdict(enriched)
        except ValueError as exc:
            report_error(
                "Bundle records an unknown risk mode",
                exc,
                event="enrich_failed",
                bundle=str(bundle_path),
            )
            raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
        enriched = refresh_cra_exploitation_signals(enriched)
        assessment = enriched.summary.risk_assessment
        payloads = {destination: enriched.model_dump_json(indent=2, exclude_none=False)}
        if (
            enriched.summary.release_status != bundle.summary.release_status
            or assessment != bundle.summary.risk_assessment
        ):
            payloads.update(_sibling_reports(enriched, bundle_path, destination))
        # One set: the bundle and its reports reach disk together or not at all.
        write_all_or_nothing(payloads)
        regenerated = sorted(path.name for path in payloads if path != destination)

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
                risk_mode=assessment.mode if assessment else "off",
                release_status=enriched.summary.release_status.value,
                reports_regenerated=regenerated,
            )
        else:
            console.print(
                "[green]enriched[/green] "
                f"evidence={report.evidence_enriched}/{report.evidence_with_cves} "
                f"cves={report.distinct_cves} kev={report.cves_in_kev} "
                # Feed dates are read from the feed files, so they are escaped.
                f"feeds: epss={escape(report.epss_feed_date or 'absent')} "
                f"kev={escape(report.kev_feed_date or 'absent')}"
            )
            if assessment is not None:
                console.print(
                    f"risk mode {assessment.mode}: "
                    f"release_status={enriched.summary.release_status.value}"
                )
            for name in regenerated:
                console.print(f"{name} regenerated → {destination.parent / name}")
            console.print(f"bundle.json → {destination}")


_REPORT_RENDERERS = {"report.md": bundle_to_markdown, "summary.html": bundle_to_html}


def _sibling_reports(bundle: EvidenceBundle, source: Path, destination: Path) -> dict[Path, str]:
    """Re-render the reports ``run`` wrote next to ``source``, placed next to ``destination``.

    Only reports that exist next to the input bundle are rendered: in place
    that overwrites the stale siblings, and with a different ``--output`` it
    writes the same set next to the output. Nothing is created out of thin air.
    """
    return {
        destination.parent / name: render(bundle)
        for name, render in _REPORT_RENDERERS.items()
        if (source.parent / name).is_file()
    }


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
    report_error(
        f"{label} feed {path} could not be used: {reason}",
        event="enrich_failed",
        feed=str(path),
        feed_kind=label,
    )
    raise typer.Exit(code=EXIT_INPUT_ERROR)


def _load_bundle(path: Path) -> EvidenceBundle:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except UNREADABLE_INPUT as exc:
        if is_json_logs():
            emit_event("enrich_failed", bundle=str(path), reason=str(exc))
        else:
            report_error(f"Could not read {path}", exc)
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
    try:
        return EvidenceBundle.model_validate(raw)
    except ValidationError as exc:
        report_error(
            "Bundle does not match the current schema", exc, event="enrich_failed", bundle=str(path)
        )
        raise typer.Exit(code=EXIT_INPUT_ERROR) from exc
