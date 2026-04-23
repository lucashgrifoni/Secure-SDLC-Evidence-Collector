"""HTML summary exporter."""

from __future__ import annotations

from pathlib import Path

from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._jinja import get_environment


def bundle_to_html(bundle: EvidenceBundle) -> str:
    env = get_environment()
    template = env.get_template("summary.html.j2")
    return template.render(bundle=bundle)


def export_html(bundle: EvidenceBundle, output_path: str | Path) -> Path:
    target = Path(output_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(bundle_to_html(bundle), encoding="utf-8")
    return target
