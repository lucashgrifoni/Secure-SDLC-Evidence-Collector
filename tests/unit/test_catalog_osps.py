"""Tests for the bundled OpenSSF OSPS Baseline catalog."""

from __future__ import annotations

from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog
from evidence_collector.domain.enums import EvidenceType


def test_osps_baseline_catalog_loads_and_is_unique() -> None:
    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    assert controls
    ids = [c.control_id for c in controls]
    assert len(ids) == len(set(ids))  # load_catalog also rejects duplicates


def test_osps_baseline_covers_the_attestable_criteria() -> None:
    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    ids = {c.control_id for c in controls}
    assert {
        "OSPS-QA-02.02",
        "OSPS-BR-06.01",
        "OSPS-VM-05.03",
        "OSPS-VM-06.02",
        "OSPS-QA-06.01",
        "OSPS-QA-07.01",
        "OSPS-QA-03.01",
    } <= ids


def test_osps_baseline_maps_controls_to_expected_evidence() -> None:
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    assert EvidenceType.SBOM in controls["OSPS-QA-02.02"].required_evidence_types
    assert EvidenceType.ARTIFACT_SIGNATURE in controls["OSPS-BR-06.01"].required_evidence_types
    assert EvidenceType.SCA_SCAN in controls["OSPS-VM-05.03"].required_evidence_types
    assert EvidenceType.SAST_SCAN in controls["OSPS-VM-06.02"].required_evidence_types
    assert EvidenceType.TEST_RESULT in controls["OSPS-QA-06.01"].required_evidence_types
    assert EvidenceType.CODE_REVIEW in controls["OSPS-QA-07.01"].required_evidence_types
    assert EvidenceType.WORKFLOW_RUN in controls["OSPS-QA-03.01"].required_evidence_types
