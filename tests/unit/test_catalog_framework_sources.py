"""Catalog claims must resolve to the inspected official mapping sources."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog

ROOT = Path(__file__).resolve().parents[2]


def test_cr26_catalog_uses_selected_actual_ids_and_explicit_partial_scope() -> None:
    controls = load_catalog("catalog-fedramp-cr26.yaml")
    assert {c.control_id for c in controls} == {
        "KSI-SCR-MIT",
        "KSI-SCR-MON",
        "KSI-CMT-VTD",
        "KSI-PIY-RSD",
        "KSI-RPL-TRC",
        "KSI-SVC-VRI",
    }
    for c in controls:
        assert c.framework.value == "ORG_INTERNAL"
        assert "supporting evidence" in c.name.lower()
        assert "partial" in c.description.lower()
        assert "2026.10.05.01" in c.description
        assert "1c33385a06acf4faf50da2b9b4dc31cd826e5b91" in c.description


def test_legacy_fedramp_ids_are_preserved_without_official_id_claims() -> None:
    controls = load_catalog("catalog-fedramp-20x-ksi.yaml")
    assert len(controls) == 10
    for c in controls:
        assert "legacy" in c.description.lower()
        assert "internal" in c.description.lower()


@pytest.mark.parametrize(
    "name", ["catalog.yaml", "catalog-ssdf-1.2.yaml", "catalog-osps-baseline.yaml"]
)
def test_embedded_csf_references_match_frozen_nist_task_export(name: str) -> None:
    source = json.loads(
        (ROOT / "docs/adr/data/0014-csf20-ssdf-references.json").read_text(encoding="utf-8")
    )
    checked: list[bool] = []
    for control in load_catalog(name):
        practice = re.search(r"(PS|PW|PO|RV)\.\d+", control.control_id + " " + control.description)
        if practice:
            expected = sorted(
                {
                    csf
                    for csf, refs in source["references"].items()
                    if any(ref.startswith("SSDF: " + practice[0] + ".") for ref in refs)
                }
            )
            if expected:
                checked.append(all(ref in control.description for ref in expected))
                checked.append(source["sha256"] in control.description)
    assert len(checked) >= 6, "Catalog must contain at least three mapped SSDF practices"
    assert all(checked), "Embedded mapping differs from the frozen official source"


def test_ai_catalog_has_no_fabricated_ssdf_task_ids() -> None:
    text = bundled_catalog_path("catalog-ai.yaml").read_text(encoding="utf-8")
    assert not re.search(r"(?:PS|PW)\.AI\.?\d*|PW\.\d+\.AI", text)
    controls = {c.control_id: c for c in load_catalog("catalog-ai.yaml")}
    assert "PO.1.2" in controls["AI-MODEL-CARD"].description
    assert "PW.3.2" in controls["AI-TRAINING-LINEAGE"].description
    assert "PW.8.2" in controls["AI-SAFETY-EVAL"].description
    assert controls["AI-MCP-INVENTORY"].framework.value == "ORG_INTERNAL"
