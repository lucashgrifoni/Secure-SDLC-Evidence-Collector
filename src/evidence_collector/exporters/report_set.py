"""The three files that together describe one release.

`bundle.json`, `report.md` and `summary.html` are not three independent
outputs — they are three renderings of the same verdict, and they are only
useful if they agree. Writing them one at a time meant they could disagree,
and nothing in any of them records which run produced it, so a stale
`report.md` next to a fresh `bundle.json` reads as the current verdict.

Exporting them as a set makes that state unreachable in every failure this
tool can actually hit: rendering happens before any file is touched, and the
staged files all reach disk before any of them is put in place.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_all_or_nothing
from evidence_collector.exporters.html import bundle_to_html
from evidence_collector.exporters.json_exporter import bundle_to_json
from evidence_collector.exporters.markdown import bundle_to_markdown

__all__ = ["ReportSet", "export_report_set"]


@dataclass(frozen=True)
class ReportSet:
    json_path: Path
    markdown_path: Path
    html_path: Path


def export_report_set(bundle: EvidenceBundle, output_dir: Path) -> ReportSet:
    """Write the whole report set for `bundle`, or leave the directory alone."""
    output_dir = Path(output_dir).expanduser()
    paths = ReportSet(
        json_path=output_dir / "bundle.json",
        markdown_path=output_dir / "report.md",
        html_path=output_dir / "summary.html",
    )
    # Render first: a template error or an unserialisable value fails here,
    # while the previous run's output is still intact and still consistent.
    write_all_or_nothing(
        {
            paths.json_path: bundle_to_json(bundle) + "\n",
            paths.markdown_path: bundle_to_markdown(bundle),
            paths.html_path: bundle_to_html(bundle),
        }
    )
    return paths
