"""Tests for SPDX 3.0.x detection and AI/Dataset/Security profile extraction.

SPDX 3.0 dropped the top-level ``spdxVersion`` / ``SPDXID`` keys for a
``@context`` + ``@graph`` of typed elements, so such SBOMs were previously
unrecognised and ignored. These tests pin detection, the profile element
counts, and that classic SPDX 2.x is unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sbom
from evidence_collector.parsers.sbom import is_spdx3, parse_sbom

SPDX3: dict[str, Any] = {
    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
    "@graph": [
        {"type": "CreationInfo", "specVersion": "3.0.1", "created": "2026-06-01T00:00:00Z"},
        {"type": "software_Sbom", "spdxId": "urn:sbom", "name": "acme-sbom"},
        {"type": "software_Package", "spdxId": "urn:pkg:lib1", "name": "lib1"},
        {"type": "software_Package", "spdxId": "urn:pkg:lib2", "name": "lib2"},
        {"type": "ai_AIPackage", "spdxId": "urn:ai:model", "name": "classifier"},
        {"type": "dataset_DatasetPackage", "spdxId": "urn:ds", "name": "trainset"},
        {"type": "security_VulnAssessmentRelationship", "spdxId": "urn:sec"},
        "not-a-dict",
    ],
}

SPDX2: dict[str, Any] = {
    "spdxVersion": "SPDX-2.3",
    "name": "app",
    "packages": [{"name": "lib", "SPDXID": "SPDXRef-lib", "versionInfo": "1.0"}],
}


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "sbom.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_is_spdx3_detects_context() -> None:
    assert is_spdx3(SPDX3)
    assert is_spdx3({"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]})
    assert not is_spdx3(SPDX2)
    assert not is_spdx3({"bomFormat": "CycloneDX"})


def test_parse_spdx3_extracts_profiles(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, SPDX3))
    assert parsed.format == "spdx"
    assert parsed.spec_version == "3.0.1"
    assert parsed.component_count == 4  # software x2 + AI + dataset packages
    assert parsed.subject_ref == "acme-sbom"
    assert parsed.spdx_ai_package_count == 1
    assert parsed.spdx_dataset_count == 1
    assert parsed.spdx_security_assessment_count == 1


def test_normalize_spdx3_surfaces_profiles(tmp_path: Path) -> None:
    ev = normalize_sbom(parse_sbom(_write(tmp_path, SPDX3)), _release())
    assert ev.metadata["spdx_profiles"] == {
        "ai_package_count": 1,
        "dataset_count": 1,
        "security_assessment_count": 1,
    }


def test_spdx2_is_unaffected(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, SPDX2))
    assert parsed.spec_version == "SPDX-2.3"
    assert parsed.spdx_ai_package_count == 0
    ev = normalize_sbom(parsed, _release())
    assert "spdx_profiles" not in ev.metadata


def test_local_collector_ingests_spdx3(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, SPDX3, name="acme.spdx.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    sbom_evidence = [e for e in report.evidence if e.evidence_type == EvidenceType.SBOM]
    assert len(sbom_evidence) == 1
    assert sbom_evidence[0].metadata.get("spdx_profiles", {}).get("ai_package_count") == 1
    assert not report.errors
