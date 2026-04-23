"""Deterministic JSON exporter for the evidence bundle.

The bundle is serialized with stable key ordering and ISO 8601 timestamps.
Determinism is a hard requirement: identical input must produce byte-for-byte
identical output so downstream auditors can verify integrity hashes.
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_collector.domain.models import EvidenceBundle


def bundle_to_json(bundle: EvidenceBundle) -> str:
    payload = bundle.model_dump(mode="json", by_alias=True)
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def export_json(bundle: EvidenceBundle, output_path: str | Path) -> Path:
    target = Path(output_path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(bundle_to_json(bundle) + "\n", encoding="utf-8")
    return target
