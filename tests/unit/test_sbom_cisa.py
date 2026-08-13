"""Tests for the CISA 2025 Minimum Elements presence check on SBOM evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

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


def test_components_nested_under_the_bom_subject_are_counted(tmp_path: Path) -> None:
    """`metadata.component` is a component, and the spec lets it nest too.

    The first pass flattened every sibling under `components[]` but reached the
    BOM subject in two places and treated it as a *leaf*. A BOM whose subject
    holds its packages — a legal, ordinary shape — therefore reported
    `component_count: 0` for a file with four components in it.
    """
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-06-01T00:00:00Z",
            "tools": [{"name": "syft"}],
            "lifecycles": [{"phase": "build"}],
            "component": {
                "type": "application",
                "name": "api",
                "version": "1.0",
                "purl": "pkg:pypi/api@1.0",
                "supplier": {"name": "Acme"},
                "hashes": [{"alg": "SHA-256", "content": "d"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "components": [
                    {
                        "type": "library",
                        "name": "flask",
                        "version": "3.0.0",
                        "purl": "pkg:pypi/flask@3.0.0",
                        "supplier": {"name": "Pallets"},
                        "hashes": [{"alg": "SHA-256", "content": "d"}],
                        "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    }
                ],
            },
        },
        "dependencies": [{"ref": "pkg:pypi/api@1.0", "dependsOn": []}],
    }

    parsed = parse_sbom(_write(tmp_path, sbom))

    assert parsed.component_count == 1
    assert all(parsed.cisa_minimum_elements.values())


def test_a_supplier_less_component_under_the_subject_breaks_conformance(
    tmp_path: Path,
) -> None:
    """The claim that broke: full conformance over a component never inspected."""
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-06-01T00:00:00Z",
            "tools": [{"name": "syft"}],
            "lifecycles": [{"phase": "build"}],
            "component": {
                "type": "application",
                "name": "api",
                "version": "1.0",
                "purl": "pkg:pypi/api@1.0",
                "supplier": {"name": "Acme"},
                "hashes": [{"alg": "SHA-256", "content": "d"}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                # No supplier, no hashes, no licenses, no purl.
                "components": [{"type": "library", "name": "vendored", "version": "0.1"}],
            },
        },
        "dependencies": [{"ref": "pkg:pypi/api@1.0", "dependsOn": []}],
    }

    elements = parse_sbom(_write(tmp_path, sbom)).cisa_minimum_elements

    assert elements["supplier"] is False
    assert elements["hash"] is False
    assert elements["license"] is False
    assert elements["unique_identifier"] is False


def test_ml_and_crypto_objects_under_the_subject_are_counted(tmp_path: Path) -> None:
    """A CBOM or ML-BOM whose subject holds the assets reported zero of them."""
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "application",
                "name": "api",
                "version": "1.0",
                "components": [
                    {"type": "machine-learning-model", "name": "m", "version": "1"},
                    {"type": "cryptographic-asset", "name": "rsa-key", "version": "1"},
                    {"type": "data", "name": "training-set", "version": "1"},
                ],
            }
        },
    }

    parsed = parse_sbom(_write(tmp_path, sbom))

    assert parsed.ml_model_count == 1
    assert parsed.crypto_asset_count == 1
    assert parsed.dataset_count == 1


def test_nesting_past_the_depth_cap_is_reported_not_silently_truncated(
    tmp_path: Path,
) -> None:
    """A partially inspected SBOM must not be reported on at all.

    The walk used to stop at the cap and return what it had, so every
    downstream check ran over a prefix and reported conformance for components
    it never opened: exit 0, `cisa_2025_conformant: true`, no warning and no
    truncation flag anywhere. `docs/limitations.md` promises an element is
    reported present only when *every* component carries it, and a claim made
    from a sample is exactly what this tool must not produce.
    """
    from evidence_collector.parsers._common import ParseError

    deepest: dict[str, Any] = {"type": "library", "name": "leaf", "version": "1"}
    node = deepest
    for index in range(1200):
        node = {
            "type": "library",
            "name": f"level-{index}",
            "version": "1",
            "components": [node],
        }
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [node]}

    with pytest.raises(ParseError) as excinfo:
        parse_sbom(_write(tmp_path, sbom))

    message = str(excinfo.value)
    assert "nest deeper than" in message
    assert "partially inspected" in message


def test_ordinary_nesting_depth_is_nowhere_near_the_cap(tmp_path: Path) -> None:
    """Real toolchains nest two or three deep; the cap must never fire on them."""
    node: dict[str, Any] = {"type": "library", "name": "leaf", "version": "1"}
    for index in range(20):
        node = {"type": "library", "name": f"l{index}", "version": "1", "components": [node]}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [node]}

    assert parse_sbom(_write(tmp_path, sbom)).component_count == 21
