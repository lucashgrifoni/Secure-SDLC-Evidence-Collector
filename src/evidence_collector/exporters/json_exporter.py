"""Deterministic JSON exporter for the evidence bundle.

The bundle is serialized with stable key ordering and ISO 8601 timestamps.
Determinism is a hard requirement: identical input must produce byte-for-byte
identical output so downstream auditors can verify integrity hashes.
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.exporters._atomic import write_atomic


def bundle_to_json(bundle: EvidenceBundle) -> str:
    payload = bundle.model_dump(mode="json", by_alias=True)
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def export_json(bundle: EvidenceBundle, output_path: str | Path) -> Path:
    return write_atomic(Path(output_path).expanduser(), bundle_to_json(bundle) + "\n")
