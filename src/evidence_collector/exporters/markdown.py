"""Markdown report exporter."""

from __future__ import annotations

from pathlib import Path

from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_atomic
from evidence_collector.exporters._jinja import get_environment


def bundle_to_markdown(bundle: EvidenceBundle) -> str:
    env = get_environment()
    template = env.get_template("report.md.j2")
    return template.render(bundle=bundle)


def export_markdown(bundle: EvidenceBundle, output_path: str | Path) -> Path:
    return write_atomic(Path(output_path).expanduser(), bundle_to_markdown(bundle))
