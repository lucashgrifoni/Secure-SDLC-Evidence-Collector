"""Tests for the CISA 2025 Minimum Elements presence check on SBOM evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sbom
from evidence_collector.parsers.sbom import _CISA_2025_ELEMENT_KEYS, parse_sbom

CDX_COMPLETE: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "metadata": {
        "timestamp": "2026-06-01T00:00:00Z",
        "authors": [{"name": "Acme"}],
        "tools": {"components": [{"name": "syft", "version": "1.0"}]},
        "lifecycles": [{"phase": "build"}],
        "component": {"name": "app", "version": "1.0", "purl": "pkg:pypi/app@1.0"},
    },
    "components": [
        {
            "name": "lib",
            "version": "2.0",
            "purl": "pkg:pypi/lib@2.0",
            "supplier": {"name": "LibCo"},
            "hashes": [{"alg": "SHA-256", "content": "abc"}],
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ],
    "dependencies": [{"ref": "pkg:pypi/app@1.0", "dependsOn": ["pkg:pypi/lib@2.0"]}],
}

CDX_INCOMPLETE: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "metadata": {"timestamp": "2026-06-01T00:00:00Z", "tools": [{"name": "x"}]},
    "components": [{"name": "lib", "version": "2.0", "purl": "pkg:pypi/lib@2.0"}],
}

SPDX_COMPLETE: dict[str, Any] = {
    "spdxVersion": "SPDX-2.3",
    "name": "app",
    "creationInfo": {
        "created": "2026-06-01T00:00:00Z",
        "creators": ["Tool: syft-1.0", "Organization: Acme"],
        "creatorComment": "Generated at the build stage",
    },
    "packages": [
        {
            "name": "lib",
            "SPDXID": "SPDXRef-lib",
            "versionInfo": "2.0",
            "supplier": "Organization: LibCo",
            "checksums": [{"algorithm": "SHA256", "checksumValue": "abc"}],
            "licenseConcluded": "MIT",
        }
    ],
    "relationships": [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-lib",
        }
    ],
}


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "sbom.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_cyclonedx_complete_meets_all_cisa_2025_elements(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, CDX_COMPLETE))
    assert set(parsed.cisa_minimum_elements) == set(_CISA_2025_ELEMENT_KEYS)
    assert all(parsed.cisa_minimum_elements.values())


def test_cyclonedx_incomplete_flags_missing_elements(tmp_path: Path) -> None:
    elements = parse_sbom(_write(tmp_path, CDX_INCOMPLETE)).cisa_minimum_elements
    assert elements["component_name"] is True
    assert elements["version"] is True
    assert elements["hash"] is False
    assert elements["license"] is False
    assert elements["supplier"] is False
    assert elements["dependency_relationships"] is False
    assert elements["generation_context"] is False
    assert not all(elements.values())


def test_spdx_complete_meets_all_cisa_2025_elements(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, SPDX_COMPLETE))
    assert set(parsed.cisa_minimum_elements) == set(_CISA_2025_ELEMENT_KEYS)
    assert all(parsed.cisa_minimum_elements.values())


def test_normalize_sbom_surfaces_cisa_conformance(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, CDX_COMPLETE))
    ev = normalize_sbom(parsed, _release())
    assert ev.metadata["cisa_2025_conformant"] is True
    assert ev.metadata["cisa_2025_minimum_elements"]["hash"] is True

    incomplete = normalize_sbom(parse_sbom(_write(tmp_path, CDX_INCOMPLETE)), _release())
    assert incomplete.metadata["cisa_2025_conformant"] is False
