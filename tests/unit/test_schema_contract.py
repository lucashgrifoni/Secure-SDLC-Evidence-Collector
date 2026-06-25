"""Freshness + self-description gate for the published bundle JSON Schema.

``docs/evidence-bundle.schema.json`` is committed so it can be served from a
stable URL (GitHub Pages) and mirrored to registries like SchemaStore. These
tests fail if it drifts from the model, so the published contract can never go
stale, and assert it carries the ``$schema``/``$id`` keywords editors need.
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_collector.schema import (
    BUNDLE_SCHEMA_DIALECT,
    BUNDLE_SCHEMA_ID,
    bundle_json_schema_text,
)

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "evidence-bundle.schema.json"


def test_committed_bundle_schema_is_in_sync() -> None:
    committed = _SCHEMA_PATH.read_text(encoding="utf-8")
    assert committed == bundle_json_schema_text(), (
        "docs/evidence-bundle.schema.json is stale — regenerate it with "
        "`sdlc-evidence schema --output docs/evidence-bundle.schema.json`"
    )


def test_committed_bundle_schema_is_self_describing() -> None:
    data = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert data["$id"] == BUNDLE_SCHEMA_ID
    assert data["$schema"] == BUNDLE_SCHEMA_DIALECT
    assert data["title"] == "EvidenceBundle"
    # The contract must keep its top-level shape (the bundle's fields).
    assert "control_evaluations" in data["properties"]
