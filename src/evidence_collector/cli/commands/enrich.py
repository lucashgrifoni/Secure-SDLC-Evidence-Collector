"""``sdlc-evidence enrich`` — attach EPSS + CISA KEV intelligence to a bundle.

Given an existing ``bundle.json``, walk every evidence record that
carries ``cve_ids`` and attach a :class:`VulnerabilityIntelligence`
summary computed from local EPSS + KEV feeds. The command is offline by
default: the user supplies feed paths via ``--epss-feed`` and
``--kev-feed``. Network refresh stays out of this CLI surface so the
collector remains side-effect-free and air-gap-friendly.

Exit codes:

* 0 — enrichment ran (with or without matches); bundle written to ``--output``.
* 2 — bundle path missing or malformed.
* 3 — feed path supplied but file unreadable / malformed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from evidence_collector.cli._logging import emit_event
from evidence_collector.cli._state import console, is_json_logs
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.intelligence import (
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
                exists=True,
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
        epss = load_epss_feed(epss_feed) if epss_feed else load_epss_feed(Path("/dev/null"))
        kev = load_kev_feed(kev_feed) if kev_feed else load_kev_feed(Path("/dev/null"))

        enriched, report = enrich_bundle(bundle, epss, kev, top_risk_limit=top_risk_limit)
        destination = output or bundle_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            enriched.model_dump_json(indent=2, exclude_none=False), encoding="utf-8"
        )

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


def _load_bundle(path: Path) -> EvidenceBundle:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if is_json_logs():
            emit_event("enrich_failed", bundle=str(path), reason=str(exc))
        else:
            console.print(f"[red]Could not read {path}:[/red] {exc}")
        raise typer.Exit(code=2) from exc
    try:
        return EvidenceBundle.model_validate(raw)
    except ValidationError as exc:
        if is_json_logs():
            emit_event("enrich_failed", bundle=str(path), reason=str(exc))
        else:
            console.print(f"[red]Bundle does not match the current schema:[/red] {exc}")
        raise typer.Exit(code=2) from exc
