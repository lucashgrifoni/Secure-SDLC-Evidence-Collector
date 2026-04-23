"""SBOM parser for CycloneDX 1.x and SPDX JSON.

Both formats are supported by reading JSON and detecting the format via
well-known keys. The parser returns a normalized view of the SBOM without
attempting to fully model each specification.
"""

from __future__ import annotations

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


@dataclass
class ParsedSbom:
    artifact: ParsedArtifact
    format: SbomFormat
    spec_version: str | None
    component_count: int
    subject_ref: str | None
    serial_number: str | None = None
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


def parse_sbom(path: str | Path) -> ParsedSbom:
    resolved = ensure_file(path)
    data = load_json(resolved)
    sbom_format = _detect_format(data, resolved)

    if sbom_format == "cyclonedx":
        spec_version = data.get("specVersion")
        serial_number = data.get("serialNumber")
        component_count = _cyclonedx_component_count(data)
        subject_ref = _cyclonedx_subject(data)
        content_type = "application/vnd.cyclonedx+json"
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
        raw=data,
    )
