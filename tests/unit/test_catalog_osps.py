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


def test_osps_baseline_catalog_pins_the_current_upstream_release() -> None:
    """v2026.08.28 is the release baseline.openssf.org labels current.

    The catalog cited v2025-02-25, three releases behind, in a hyphenated
    form upstream does not use. The pin names the tag and its commit so the
    exact source text can be fetched again.
    """
    text = bundled_catalog_path("catalog-osps-baseline.yaml").read_text(encoding="utf-8")
    assert "v2026.08.28" in text
    assert "a26a7963f6fd098c1e82829322ec9e1196a4f294" in text
    assert "v2025-02-25" not in text


def test_osps_qa_07_01_names_a_human_approval_and_its_limit() -> None:
    """v2026.08.28 requires a non-author *human* approval.

    Code-review evidence counts approvals by reviewer login and cannot tell a
    bot account from a person, so the description says what is left to review.
    """
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    description = controls["OSPS-QA-07.01"].description
    assert "non-author human approval" in description
    assert "bot" in description


def test_osps_baseline_adds_attestable_controls_as_recommended_only() -> None:
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    threat_model = controls["OSPS-SA-03.02"]
    assert threat_model.required_evidence_types == []
    assert threat_model.recommended_evidence_types == [EvidenceType.THREAT_MODEL]
    version_id = controls["OSPS-BR-02.01"]
    assert version_id.required_evidence_types == []
    assert version_id.recommended_evidence_types == [EvidenceType.ARTIFACT_ATTESTATION]
    # VM-04.02 needs VEX documents as evidence and DO-05.01 an end-of-support
    # statement; neither is an evidence type the collector reads yet.
    assert "OSPS-VM-04.02" not in controls
    assert "OSPS-DO-05.01" not in controls
