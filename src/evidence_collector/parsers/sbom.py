"""SBOM parser for CycloneDX 1.x and SPDX JSON.

Both formats are supported by reading JSON and detecting the format via
well-known keys. The parser returns a normalized view of the SBOM without
attempting to fully model each specification.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
    load_json,
)

SbomFormat = Literal["cyclonedx", "spdx"]

_CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class CycloneDxVulnerabilityAnalysis:
    """Inline VEX-shaped analysis carried by a CycloneDX vulnerability.

    CycloneDX 1.4+ allows embedding a ``vulnerabilities[*].analysis`` block
    that restates an exploitability decision (state, justification,
    response, detail). CycloneDX 1.7 makes this the canonical place to
    carry VEX so SBOM and VEX no longer need to travel as separate files.
    We surface the analysis as-is, without translating to OpenVEX here;
    the OpenVEX exporter does the mapping when it builds the document.
    """

    cve_id: str
    state: str | None = None
    justification: str | None = None
    responses: list[str] = field(default_factory=list)
    detail: str | None = None


@dataclass
class ParsedSbom:
    artifact: ParsedArtifact
    format: SbomFormat
    spec_version: str | None
    component_count: int
    subject_ref: str | None
    serial_number: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    lifecycle_phases: list[str] = field(default_factory=list)
    vulnerability_analyses: list[CycloneDxVulnerabilityAnalysis] = field(default_factory=list)
    cisa_minimum_elements: dict[str, bool] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def _detect_format(data: dict[str, Any], path: Path) -> SbomFormat:
    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        return "cyclonedx"
    if "spdxVersion" in data or "SPDXID" in data:
        return "spdx"
    raise ParseError(f"Unknown SBOM format in {path}")


def _cyclonedx_component_count(data: dict[str, Any]) -> int:
    components = data.get("components")
    if isinstance(components, list):
        return sum(1 for c in components if isinstance(c, dict))
    return 0


def _cyclonedx_subject(data: dict[str, Any]) -> str | None:
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    purl = component.get("purl")
    if isinstance(purl, str) and purl:
        return purl
    name = component.get("name")
    version = component.get("version")
    if isinstance(name, str) and name:
        return f"{name}@{version}" if isinstance(version, str) and version else name
    return None


def _spdx_component_count(data: dict[str, Any]) -> int:
    packages = data.get("packages")
    if isinstance(packages, list):
        return sum(1 for p in packages if isinstance(p, dict))
    return 0


def _spdx_subject(data: dict[str, Any]) -> str | None:
    name = data.get("name")
    if isinstance(name, str) and name:
        return name
    return None


def _collect_cves_from_string(value: Any, sink: set[str]) -> None:
    """Append every CVE id found in ``value`` (if it is a string) to ``sink``."""
    if isinstance(value, str):
        for match in _CVE_PATTERN.findall(value):
            sink.add(match.upper())


def _collect_cves_from_references(references: Any, sink: set[str]) -> None:
    """Append every CVE id found across CycloneDX ``references[*].id`` entries."""
    if not isinstance(references, list):
        return
    for ref in references:
        if isinstance(ref, dict):
            _collect_cves_from_string(ref.get("id"), sink)


def _cyclonedx_cve_ids(data: dict[str, Any]) -> list[str]:
    """Extract distinct CVE IDs from a CycloneDX BOM's vulnerabilities block.

    CycloneDX 1.4+ allows embedding vulnerabilities directly in the SBOM
    (``vulnerabilities[*].id`` plus optional ``references[*].id`` for
    cross-references like CVE→GHSA mappings). We collect both.
    """
    found: set[str] = set()
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        _collect_cves_from_string(vuln.get("id"), found)
        _collect_cves_from_references(vuln.get("references"), found)
    return sorted(found)


def _cyclonedx_lifecycle_phases(data: dict[str, Any]) -> list[str]:
    """Extract ``metadata.lifecycles[*]`` phase identifiers from a CycloneDX BOM.

    CycloneDX 1.7 promotes lifecycle awareness into the SBOM. Each entry
    can be either a predefined phase (``phase``: "build", "operations",
    etc.) or a custom phase (``name`` + ``description``). We preserve the
    raw string from whichever field is populated so consumers can decide
    how to interpret custom phases.
    """
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        return []
    lifecycles = metadata.get("lifecycles")
    if not isinstance(lifecycles, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for entry in lifecycles:
        if not isinstance(entry, dict):
            continue
        phase = entry.get("phase")
        if isinstance(phase, str) and phase.strip():
            key = phase.strip()
        else:
            name = entry.get("name")
            key = name.strip() if isinstance(name, str) and name.strip() else ""
        if key and key not in seen:
            out.append(key)
            seen.add(key)
    return out


def _cyclonedx_vulnerability_analyses(
    data: dict[str, Any],
) -> list[CycloneDxVulnerabilityAnalysis]:
    """Extract ``vulnerabilities[*].analysis`` inline VEX from a CycloneDX BOM.

    Returns one entry per CVE that carries an ``analysis`` block. The
    CycloneDX vocabulary is preserved as-is (state, justification,
    response); the OpenVEX exporter maps it to OpenVEX statements.
    """
    out: list[CycloneDxVulnerabilityAnalysis] = []
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        analysis = vuln.get("analysis")
        if not isinstance(analysis, dict):
            continue
        cve_id_raw = vuln.get("id")
        if not isinstance(cve_id_raw, str):
            continue
        match = _CVE_PATTERN.search(cve_id_raw)
        if match is None:
            continue
        responses_raw = analysis.get("response")
        responses: list[str] = []
        if isinstance(responses_raw, list):
            responses = [r for r in responses_raw if isinstance(r, str) and r]
        state = analysis.get("state") if isinstance(analysis.get("state"), str) else None
        justification = (
            analysis.get("justification")
            if isinstance(analysis.get("justification"), str)
            else None
        )
        detail = analysis.get("detail") if isinstance(analysis.get("detail"), str) else None
        out.append(
            CycloneDxVulnerabilityAnalysis(
                cve_id=match.group(0).upper(),
                state=state,
                justification=justification,
                responses=responses,
                detail=detail,
            )
        )
    return out


# CISA "2025 Minimum Elements for a Software Bill of Materials"
# (https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)
# consolidates the 2021 NTIA baseline (author, timestamp, supplier,
# component name, version, unique identifier, dependency relationships) with
# the 2025 additions (component hash, license, tool name, generation context).
# The collector checks *presence* per the project's evidence-quality stance
# (docs/limitations.md §3): a component-level element is reported present only
# when every component carries it; a document-level element when the document
# carries it. This turns "an SBOM exists" into "the SBOM is shaped like a
# conformant one" — it does not validate the correctness of the values.
_CISA_2025_ELEMENT_KEYS: tuple[str, ...] = (
    "author",
    "timestamp",
    "supplier",
    "component_name",
    "version",
    "unique_identifier",
    "dependency_relationships",
    "hash",
    "license",
    "tool",
    "generation_context",
)

# SPDX relationshipType values that express an actual dependency / inclusion
# graph. A document-to-package ``DESCRIBES`` (or its inverse) is NOT a
# dependency relationship, so it must not satisfy CISA's dependency element.
_SPDX_DEPENDENCY_RELATIONSHIP_TYPES: frozenset[str] = frozenset(
    {
        "DEPENDS_ON",
        "DEPENDENCY_OF",
        "BUILD_DEPENDENCY_OF",
        "DEV_DEPENDENCY_OF",
        "OPTIONAL_DEPENDENCY_OF",
        "PROVIDED_DEPENDENCY_OF",
        "RUNTIME_DEPENDENCY_OF",
        "TEST_DEPENDENCY_OF",
        "CONTAINS",
        "CONTAINED_BY",
        "STATIC_LINK",
        "DYNAMIC_LINK",
        "PREREQUISITE_FOR",
        "HAS_PREREQUISITE",
    }
)


def _canonical(elements: dict[str, bool]) -> dict[str, bool]:
    """Return the element map in the canonical CISA key order; indexing each
    key also asserts both format builders emit the full element set."""
    return {key: elements[key] for key in _CISA_2025_ELEMENT_KEYS}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _all_components_have(
    components: list[Any], predicate: Callable[[dict[str, Any]], bool]
) -> bool:
    real = [c for c in components if isinstance(c, dict)]
    return bool(real) and all(predicate(c) for c in real)


def _cyclonedx_cisa_elements(data: dict[str, Any]) -> dict[str, bool]:
    metadata = _as_dict(data.get("metadata"))
    components = _as_list(data.get("components"))
    # CISA's component-level elements apply to every component, including the
    # top-level subject in metadata.component. Without this an application
    # with no supplier/hash/license is masked by complete dependencies.
    subject = metadata.get("component")
    if isinstance(subject, dict):
        components = [subject, *components]
    tools = metadata.get("tools")
    has_tool = (
        bool(tools)
        if isinstance(tools, list)
        else isinstance(tools, dict) and bool(tools.get("components") or tools.get("services"))
    )
    authors = metadata.get("authors")
    has_author = (isinstance(authors, list) and bool(authors)) or has_tool
    lifecycles = metadata.get("lifecycles")
    elements = {
        "author": bool(has_author),
        "timestamp": bool(metadata.get("timestamp")),
        "supplier": _all_components_have(
            components, lambda c: bool(c.get("supplier") or c.get("publisher") or c.get("author"))
        ),
        "component_name": _all_components_have(components, lambda c: bool(c.get("name"))),
        "version": _all_components_have(components, lambda c: bool(c.get("version"))),
        "unique_identifier": _all_components_have(
            components, lambda c: bool(c.get("purl") or c.get("cpe") or c.get("bom-ref"))
        ),
        "dependency_relationships": bool(
            isinstance(data.get("dependencies"), list) and data.get("dependencies")
        ),
        "hash": _all_components_have(components, lambda c: bool(c.get("hashes"))),
        "license": _all_components_have(components, lambda c: bool(c.get("licenses"))),
        "tool": bool(has_tool),
        "generation_context": bool(isinstance(lifecycles, list) and lifecycles),
    }
    return _canonical(elements)


def _spdx_cisa_elements(data: dict[str, Any]) -> dict[str, bool]:
    creation = _as_dict(data.get("creationInfo"))
    creators_list = _as_list(creation.get("creators"))
    has_tool = any(isinstance(c, str) and c.startswith("Tool:") for c in creators_list)
    has_author = (
        any(
            isinstance(c, str) and (c.startswith("Person:") or c.startswith("Organization:"))
            for c in creators_list
        )
        or has_tool
    )
    packages = _as_list(data.get("packages"))
    comment = creation.get("creatorComment")
    gen_context = isinstance(comment, str) and any(
        stage in comment.lower() for stage in ("source", "build", "binary")
    )
    elements = {
        "author": bool(has_author),
        "timestamp": bool(creation.get("created")),
        "supplier": _all_components_have(
            packages, lambda p: bool(p.get("supplier") or p.get("originator"))
        ),
        "component_name": _all_components_have(packages, lambda p: bool(p.get("name"))),
        "version": _all_components_have(packages, lambda p: bool(p.get("versionInfo"))),
        "unique_identifier": _all_components_have(
            packages, lambda p: bool(p.get("SPDXID") or p.get("externalRefs"))
        ),
        "dependency_relationships": any(
            isinstance(r, dict)
            and isinstance(r.get("relationshipType"), str)
            and r["relationshipType"].upper() in _SPDX_DEPENDENCY_RELATIONSHIP_TYPES
            for r in _as_list(data.get("relationships"))
        ),
        "hash": _all_components_have(packages, lambda p: bool(p.get("checksums"))),
        "license": _all_components_have(
            packages, lambda p: bool(p.get("licenseConcluded") or p.get("licenseDeclared"))
        ),
        "tool": bool(has_tool),
        "generation_context": bool(gen_context),
    }
    return _canonical(elements)


def parse_sbom(path: str | Path) -> ParsedSbom:
    resolved = ensure_file(path)
    data = load_json(resolved)
    sbom_format = _detect_format(data, resolved)

    cve_ids: list[str] = []
    lifecycle_phases: list[str] = []
    vulnerability_analyses: list[CycloneDxVulnerabilityAnalysis] = []
    cisa_elements: dict[str, bool] = {}
    if sbom_format == "cyclonedx":
        spec_version = data.get("specVersion")
        serial_number = data.get("serialNumber")
        component_count = _cyclonedx_component_count(data)
        subject_ref = _cyclonedx_subject(data)
        content_type = "application/vnd.cyclonedx+json"
        cve_ids = _cyclonedx_cve_ids(data)
        lifecycle_phases = _cyclonedx_lifecycle_phases(data)
        vulnerability_analyses = _cyclonedx_vulnerability_analyses(data)
        cisa_elements = _cyclonedx_cisa_elements(data)
    else:
        spec_version = data.get("spdxVersion")
        serial_number = data.get("documentNamespace")
        component_count = _spdx_component_count(data)
        subject_ref = _spdx_subject(data)
        content_type = "application/spdx+json"
        cisa_elements = _spdx_cisa_elements(data)

    artifact = describe(resolved, content_type=content_type)
    return ParsedSbom(
        artifact=artifact,
        format=sbom_format,
        spec_version=str(spec_version) if spec_version else None,
        component_count=component_count,
        subject_ref=subject_ref,
        serial_number=str(serial_number) if serial_number else None,
        cve_ids=cve_ids,
        lifecycle_phases=lifecycle_phases,
        vulnerability_analyses=vulnerability_analyses,
        cisa_minimum_elements=cisa_elements,
        raw=data,
    )
