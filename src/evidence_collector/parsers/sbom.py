"""SBOM parser for CycloneDX 1.x and SPDX JSON.

Both formats are supported by reading JSON and detecting the format via
well-known keys. The parser returns a normalized view of the SBOM without
attempting to fully model each specification.
"""

from __future__ import annotations

import re
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
class ParsedSbom:
    artifact: ParsedArtifact
    format: SbomFormat
    spec_version: str | None
    component_count: int
    subject_ref: str | None
    serial_number: str | None = None
    cve_ids: list[str] = field(default_factory=list)
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


def parse_sbom(path: str | Path) -> ParsedSbom:
    resolved = ensure_file(path)
    data = load_json(resolved)
    sbom_format = _detect_format(data, resolved)

    cve_ids: list[str] = []
    if sbom_format == "cyclonedx":
        spec_version = data.get("specVersion")
        serial_number = data.get("serialNumber")
        component_count = _cyclonedx_component_count(data)
        subject_ref = _cyclonedx_subject(data)
        content_type = "application/vnd.cyclonedx+json"
        cve_ids = _cyclonedx_cve_ids(data)
    else:
        spec_version = data.get("spdxVersion")
        serial_number = data.get("documentNamespace")
        component_count = _spdx_component_count(data)
        subject_ref = _spdx_subject(data)
        content_type = "application/spdx+json"

    artifact = describe(resolved, content_type=content_type)
    return ParsedSbom(
        artifact=artifact,
        format=sbom_format,
        spec_version=str(spec_version) if spec_version else None,
        component_count=component_count,
        subject_ref=subject_ref,
        serial_number=str(serial_number) if serial_number else None,
        cve_ids=cve_ids,
        raw=data,
    )
