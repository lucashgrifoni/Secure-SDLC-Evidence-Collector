"""Tests for the OSCAL Catalog exporter (T4.3)."""

from __future__ import annotations

import uuid

from evidence_collector.controls import default_catalog
from evidence_collector.exporters.oscal import export_oscal_catalog


def test_export_produces_top_level_catalog_envelope() -> None:
    payload = export_oscal_catalog(default_catalog())
    assert "catalog" in payload
    catalog = payload["catalog"]
    # OSCAL Catalog must carry a uuid, metadata, and groups.
    assert "uuid" in catalog
    assert "metadata" in catalog
    assert "groups" in catalog
    # OSCAL version must be declared so importers know the schema.
    assert catalog["metadata"]["oscal-version"].startswith("1.1")


def test_uuids_are_stable_across_runs() -> None:
    a = export_oscal_catalog(default_catalog())
    b = export_oscal_catalog(default_catalog())
    # The catalog uuid is derived from a fixed namespace, so two runs
    # must produce identical uuids — important for diffs and signing.
    assert a["catalog"]["uuid"] == b["catalog"]["uuid"]
    a_ids = sorted(c["uuid"] for g in a["catalog"]["groups"] for c in g["controls"])
    b_ids = sorted(c["uuid"] for g in b["catalog"]["groups"] for c in g["controls"])
    assert a_ids == b_ids
    # Spot-check that uuids are valid v5 UUIDs.
    for uuid_str in a_ids:
        parsed = uuid.UUID(uuid_str)
        assert parsed.version == 5


def test_controls_are_grouped_by_framework() -> None:
    payload = export_oscal_catalog(default_catalog())
    group_ids = {g["id"] for g in payload["catalog"]["groups"]}
    # Default catalog contains NIST SSDF, OWASP SAMM, and org-internal
    # controls per CHANGELOG 1.0.0, so all three groups must appear.
    assert {"nist-ssdf", "owasp-samm", "org-internal"} <= group_ids


def test_every_control_carries_required_props_and_parts() -> None:
    payload = export_oscal_catalog(default_catalog())
    control_count = 0
    for group in payload["catalog"]["groups"]:
        for control in group["controls"]:
            control_count += 1
            prop_names = {p["name"] for p in control["props"]}
            assert {"control_id", "framework", "criticality"} <= prop_names
            assert any(p["name"] == "statement" for p in control["parts"])
            assert control["class"].startswith("criticality-")
    # Lock the count so accidental drift is visible.
    assert control_count == 13
