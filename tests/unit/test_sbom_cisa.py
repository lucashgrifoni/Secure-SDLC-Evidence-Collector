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
        "component": {
            "name": "app",
            "version": "1.0",
            "purl": "pkg:pypi/app@1.0",
            "supplier": {"name": "Acme"},
            "hashes": [{"alg": "SHA-256", "content": "def456"}],
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
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
            "relatedSpdxElement": "SPDXRef-app",
        },
        {
            "spdxElementId": "SPDXRef-app",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-lib",
        },
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


def test_cyclonedx_subject_component_is_held_to_the_same_bar(tmp_path: Path) -> None:
    # The subject in metadata.component lacks a license; its dependency is
    # complete. The subject must not be masked by complete dependencies.
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-06-01T00:00:00Z",
            "tools": [{"name": "x"}],
            "lifecycles": [{"phase": "build"}],
            "component": {
                "name": "app",
                "version": "1.0",
                "purl": "pkg:pypi/app@1.0",
                "supplier": {"name": "Acme"},
                "hashes": [{"alg": "SHA-256", "content": "d"}],
            },
        },
        "components": [
            {
                "name": "lib",
                "version": "2.0",
                "purl": "pkg:pypi/lib@2.0",
                "supplier": {"name": "LibCo"},
                "hashes": [{"alg": "SHA-256", "content": "a"}],
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
        "dependencies": [{"ref": "pkg:pypi/app@1.0", "dependsOn": ["pkg:pypi/lib@2.0"]}],
    }
    elements = parse_sbom(_write(tmp_path, sbom)).cisa_minimum_elements
    assert elements["license"] is False
    assert elements["supplier"] is True


def test_spdx_describes_only_is_not_a_dependency_graph(tmp_path: Path) -> None:
    sbom = dict(SPDX_COMPLETE)
    sbom["relationships"] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-lib",
        }
    ]
    elements = parse_sbom(_write(tmp_path, sbom)).cisa_minimum_elements
    assert elements["dependency_relationships"] is False


def _nested_container_bom(inner_extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """A container SBOM shaped the way Syft and Trivy actually emit one.

    CycloneDX expresses containment through `component.components`: the OS
    component holds its distro packages, the application component holds its
    libraries. Nothing at the top level names them.
    """
    inner: dict[str, Any] = {
        "type": "library",
        "name": "openssl",
        "version": "3.0.11",
        "purl": "pkg:deb/debian/openssl@3.0.11",
    }
    inner.update(inner_extra or {})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-06-01T00:00:00Z",
            "tools": [{"name": "syft"}],
            "lifecycles": [{"phase": "build"}],
            "component": {
                "type": "container",
                "name": "acme/api",
                "version": "1.0",
                "purl": "pkg:oci/api@1.0",
                "supplier": {"name": "Acme"},
                "hashes": [{"alg": "SHA-256", "content": "d"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        },
        "components": [
            {
                "type": "operating-system",
                "name": "debian",
                "version": "12",
                "purl": "pkg:generic/debian@12",
                "supplier": {"name": "Debian"},
                "hashes": [{"alg": "SHA-256", "content": "d"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "components": [inner],
            }
        ],
        "dependencies": [{"ref": "pkg:oci/api@1.0", "dependsOn": []}],
    }


def test_nested_components_are_counted(tmp_path: Path) -> None:
    """A container SBOM's packages live one level down and were invisible.

    Reading only `components[]` counted the OS wrapper and missed every
    package inside it, so a 400-package image was recorded as
    `component_count: 1` — an SBOM that looks nearly empty in the bundle while
    the file itself is complete.
    """
    parsed = parse_sbom(_write(tmp_path, _nested_container_bom()))
    # The debian wrapper plus the openssl package inside it; before this the
    # count was 1.
    assert parsed.component_count == 2


def test_cisa_elements_are_checked_against_nested_components_too(tmp_path: Path) -> None:
    """Conformance must be reported over the components it actually examined.

    `_all_components_have` ran over the top-level slice only. A container SBOM
    whose nested packages carry no supplier still reported `supplier: true`,
    because the check inspected two wrappers and never opened them. Claiming
    CISA conformance from a sample is the one thing a conformance signal
    cannot do.
    """
    complete = parse_sbom(
        _write(
            tmp_path,
            _nested_container_bom(
                {
                    "supplier": {"name": "Debian"},
                    "hashes": [{"alg": "SHA-256", "content": "d"}],
                    "licenses": [{"license": {"id": "OpenSSL"}}],
                }
            ),
            name="complete.json",
        )
    ).cisa_minimum_elements
    assert complete["supplier"] is True
    assert complete["hash"] is True
    assert complete["license"] is True

    # Same BOM, but the nested package has no supplier, hash or license.
    incomplete = parse_sbom(
        _write(tmp_path, _nested_container_bom(), name="incomplete.json")
    ).cisa_minimum_elements
    assert incomplete["supplier"] is False
    assert incomplete["hash"] is False
    assert incomplete["license"] is False
    # The elements the nested component does satisfy stay true.
    assert incomplete["component_name"] is True
    assert incomplete["version"] is True


def test_deeply_nested_components_do_not_crash_the_parser(tmp_path: Path) -> None:
    """An SBOM is untrusted input; nesting depth must not become a crash.

    A recursive walk would hit Python's recursion limit on a hostile or
    machine-generated file and raise RecursionError, which is not a
    `ParseError` and so escapes the collector's handling entirely.
    """
    deepest: dict[str, Any] = {"type": "library", "name": "leaf", "version": "1"}
    node = deepest
    for index in range(500):
        node = {
            "type": "library",
            "name": f"level-{index}",
            "version": "1",
            "components": [node],
        }
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [node]}

    parsed = parse_sbom(_write(tmp_path, sbom))

    # Bounded, not crashed: the depth cap stops the walk without an exception.
    assert 0 < parsed.component_count <= 501
