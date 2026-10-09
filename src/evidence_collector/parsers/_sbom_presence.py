"""Bounded presence maps for CISA 2026 and the voluntary G7 AI SBOM guidance.

These are project interpretations of explicit input fields, not schema,
signature, applicability, accuracy, or regulatory compliance verification.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

CISA_2026_SOURCE = "https://www.cyber.gov.au/publication/2026-minimum-elements-for-a-software-bill-of-materials-sbom"
G7_AI_SOURCE = (
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.pdf"
)
CISA_2026_KEYS = (
    "component_dependency_relationship",
    "component_hash_algorithm",
    "component_hash_value",
    "component_identifiers",
    "component_license",
    "component_name",
    "component_producer",
    "component_version",
    "sbom_author",
    "sbom_author_signature",
    "sbom_data_format_name",
    "sbom_data_format_version",
    "sbom_generation_context",
    "sbom_timestamp",
    "sbom_tool_name",
    "sbom_tool_version",
    "sbom_version",
)
G7_CLUSTERS = {
    "metadata": (
        "sbom_author",
        "sbom_version",
        "sbom_data_format_name",
        "sbom_data_format_version",
        "sbom_author_signature",
        "sbom_tool_name",
        "sbom_tool_version",
        "sbom_generation_context",
        "sbom_timestamp",
        "sbom_dependency_relationship",
    ),
    "system": (
        "system_name",
        "system_components",
        "system_producer",
        "system_version",
        "system_timestamp",
        "system_data_flow",
        "system_data_usage",
        "system_input_output_properties",
        "intended_application_area",
    ),
    "models": (
        "model_name",
        "model_identifier",
        "model_version",
        "model_timestamp",
        "model_producer",
        "model_description",
        "model_hash_value",
        "model_hash_algorithm",
        "model_properties",
        "model_input_output_properties",
        "model_training_properties",
        "model_license",
        "model_external_references",
    ),
    "datasets": (
        "dataset_name",
        "dataset_description",
        "dataset_content",
        "dataset_identifier",
        "dataset_hash",
        "dataset_provenance",
        "dataset_statistical_properties",
        "dataset_sensitivity",
        "dataset_dependency_relationship",
        "dataset_license",
    ),
    "infrastructure": ("infrastructure_software", "infrastructure_hardware"),
    "security": (
        "security_controls",
        "security_compliance",
        "cybersecurity_policy_information",
        "vulnerability_referencing",
    ),
    "kpi": ("security_metrics", "operational_performance_kpis"),
}
PRESENT, DECLARED_UNKNOWN, ABSENT = "present", "declared_unknown", "absent"
NOT_MACHINE_CHECKABLE, UNSUPPORTED_MAPPING = "not_machine_checkable", "unsupported_mapping"
# Every status an element can carry. `declared_unknown` is an explicit
# NOASSERTION/NONE/UNKNOWN marker, which CISA 2026 asks authors to state;
# `absent` is a missing or empty field. `not_machine_checkable` means the
# input format cannot show it; `unsupported_mapping` means the format has a
# field this project does not map yet.
PRESENCE_STATES = (PRESENT, DECLARED_UNKNOWN, ABSENT, NOT_MACHINE_CHECKABLE, UNSUPPORTED_MAPPING)
_DECLARED_UNKNOWN = {"NONE", "NOASSERTION", "UNKNOWN"}
_EMPTY = {"", "N/A", "NULL"}
_RANK = {PRESENT: 0, DECLARED_UNKNOWN: 1, ABSENT: 2}
# Identifier types that serve as a lookup key outside the document. SPDXID and
# bom-ref are document-local and do not count.
_SPDX2_IDENTIFIER_REF_TYPES = {
    "purl",
    "maven-central",
    "npm",
    "nuget",
    "bower",
    "cpe22type",
    "cpe23type",
    "swid",
    "swh",
    "gitoid",
}
_SPDX3_IDENTIFIER_TYPES = {"packageurl", "cpe22", "cpe23", "swid", "swhid", "gitoid"}
# SPDX 2.3 relationships where one element is needed for the other to operate.
# Build, development, test and optional dependencies and derivation are excluded.
_SPDX2_OPERATIONAL_RELATIONSHIPS = {
    "DEPENDS_ON",
    "DEPENDENCY_OF",
    "RUNTIME_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF",
    "STATIC_LINK",
    "DYNAMIC_LINK",
    "PREREQUISITE_FOR",
    "HAS_PREREQUISITE",
    "CONTAINS",
    "CONTAINED_BY",
}
# G7 keys the CycloneDX branch maps; SPDX 3 has fields for them that are not mapped.
_G7_CDX_MAPPED = {
    "metadata": ("sbom_dependency_relationship",),
    "system": ("system_name", "system_components", "system_producer", "system_version"),
    "models": (
        "model_description",
        "model_license",
        "model_version",
        "model_producer",
        "model_hash_value",
        "model_hash_algorithm",
        "model_external_references",
    ),
    "datasets": ("dataset_description", "dataset_license", "dataset_hash"),
    "security": ("vulnerability_referencing",),
}


def _state(value: Any) -> str:
    if not isinstance(value, str):
        return ABSENT
    text = value.strip().upper()
    if text in _DECLARED_UNKNOWN:
        return DECLARED_UNKNOWN
    return ABSENT if text in _EMPTY else PRESENT


def _known(value: Any) -> bool:
    return _state(value) == PRESENT


def _best(states: Iterable[str]) -> str:
    """Any-of: the strongest state among the alternatives."""
    return min(states, key=_RANK.__getitem__, default=ABSENT)


def _worst(states: Iterable[str]) -> str:
    """All-of: the weakest state among the members."""
    return max(states, key=_RANK.__getitem__, default=ABSENT)


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _as_state(value: bool | str) -> str:
    if isinstance(value, str):
        return value
    return PRESENT if value else ABSENT


def _every(objects: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool | str]) -> str:
    """Every object must carry the element; one missing object makes it absent."""
    if not objects:
        return ABSENT
    return _worst(_as_state(predicate(obj)) for obj in objects)


def _entry(present: bool | str | None, source: str) -> dict[str, str]:
    status = NOT_MACHINE_CHECKABLE if present is None else _as_state(present)
    return {"status": status, "source": source}


def _hash(c: dict[str, Any], *, spdx: bool = False) -> str:
    return _best(
        _worst(
            (
                _state(h.get("algorithm" if spdx else "alg")),
                _state(h.get("checksumValue" if spdx else "content")),
            )
        )
        for h in _objects(c.get("checksums" if spdx else "hashes"))
    )


def _producer(c: dict[str, Any]) -> str:
    return _best(
        (
            _state(_dict(c.get("supplier")).get("name")),
            _state(c.get("publisher")),
            _state(c.get("author")),
        )
    )


def _license(c: dict[str, Any]) -> str:
    return _best(
        _best(
            (
                _state(license_entry.get("expression")),
                _state(_dict(license_entry.get("license")).get("id")),
                _state(_dict(license_entry.get("license")).get("name")),
            )
        )
        for license_entry in _objects(c.get("licenses"))
    )


def _strings(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _cdx_identifier(c: dict[str, Any]) -> str:
    """purl, cpe, SWID tagId, SWHID or OmniBOR id; bom-ref is document-local."""
    candidates = [c.get("purl"), c.get("cpe"), _dict(c.get("swid")).get("tagId")]
    candidates += _strings(c.get("swhid")) + _strings(c.get("omniborId"))
    return _best(_state(v) for v in candidates)


def _spdx2_identifier(p: dict[str, Any]) -> str:
    return _best(
        _state(ref.get("referenceLocator"))
        for ref in _objects(p.get("externalRefs"))
        if str(ref.get("referenceType", "")).lower() in _SPDX2_IDENTIFIER_REF_TYPES
    )


def _spdx3_identifier(p: dict[str, Any]) -> str:
    candidates = [p.get("software_packageUrl")] + [
        ref.get("identifier")
        for ref in _objects(p.get("externalIdentifier"))
        if str(ref.get("externalIdentifierType", "")).lower() in _SPDX3_IDENTIFIER_TYPES
    ]
    return _best(_state(v) for v in candidates)


def _cdx_relationships(data: dict[str, Any], components: list[dict[str, Any]]) -> str:
    refs = {
        d["ref"]
        for d in _objects(data.get("dependencies"))
        if _known(d.get("ref"))
        and isinstance(d.get("dependsOn"), list)
        and all(_known(r) for r in d["dependsOn"])
    }
    return _every(components, lambda c: _known(c.get("bom-ref")) and c["bom-ref"] in refs)


def cisa_presence(
    data: dict[str, Any], fmt: str, components: list[dict[str, Any]], *, spdx3: bool = False
) -> dict[str, Any]:
    elements = {
        k: _entry(UNSUPPORTED_MAPPING, "No supported field mapping") for k in CISA_2026_KEYS
    }

    def put(key: str, value: bool | str | None, source: str) -> None:
        elements[key] = _entry(value, source)

    if fmt == "cyclonedx":
        meta = _dict(data.get("metadata"))
        tools = meta.get("tools")
        tool_objects = (
            _objects(tools)
            if isinstance(tools, list)
            else _objects(_dict(tools).get("components")) + _objects(_dict(tools).get("services"))
        )
        put(
            "sbom_author",
            _best(_state(a.get("name")) for a in _objects(meta.get("authors"))),
            "metadata.authors[].name",
        )
        put(
            "sbom_version",
            isinstance(data.get("version"), int)
            and not isinstance(data.get("version"), bool)
            and data["version"] > 0,
            "version (explicit)",
        )
        put("sbom_data_format_name", data.get("bomFormat") == "CycloneDX", "bomFormat")
        put("sbom_data_format_version", _known(data.get("specVersion")), "specVersion")
        put("sbom_timestamp", _state(meta.get("timestamp")), "metadata.timestamp")
        put(
            "sbom_author_signature",
            None,
            "signature (author identity and cryptography require verification)"
            if data.get("signature")
            else "no inline signature; detached signatures are not inspected",
        )
        put(
            "sbom_tool_name",
            _every(tool_objects, lambda t: _state(t.get("name"))),
            "metadata.tools",
        )
        put(
            "sbom_tool_version",
            _every(
                tool_objects, lambda t: _worst((_state(t.get("name")), _state(t.get("version"))))
            ),
            "metadata.tools[].version",
        )
        put(
            "sbom_generation_context",
            _best(
                _best((_state(lifecycle.get("phase")), _state(lifecycle.get("name"))))
                for lifecycle in _objects(meta.get("lifecycles"))
            ),
            "metadata.lifecycles",
        )
        put(
            "component_name",
            _every(components, lambda c: _state(c.get("name"))),
            "all components[].name, including subject and descendants",
        )
        put(
            "component_version",
            _every(components, lambda c: _state(c.get("version"))),
            "all components[].version",
        )
        put(
            "component_producer",
            _every(components, _producer),
            "all components[].supplier.name/publisher/author",
        )
        put(
            "component_identifiers",
            _every(components, _cdx_identifier),
            "all components[].purl/cpe/swid.tagId/swhid/omniborId (not bom-ref)",
        )
        for key in ("component_hash_algorithm", "component_hash_value"):
            put(
                key,
                _every(components, _hash),
                "all components[].hashes[].alg and content in the same record",
            )
        put("component_license", _every(components, _license), "all components[].licenses")
        put(
            "component_dependency_relationship",
            _cdx_relationships(data, components),
            "dependencies[].ref and explicit dependsOn for every component",
        )
    elif not spdx3:
        creation = _dict(data.get("creationInfo"))
        creators = creation.get("creators")
        creators = creators if isinstance(creators, list) else []
        packages = _objects(data.get("packages"))
        put(
            "sbom_author",
            _best(
                _state(c.split(":", 1)[1])
                for c in creators
                if isinstance(c, str) and c.startswith(("Person:", "Organization:"))
            ),
            "creationInfo.creators (Person/Organization)",
        )
        put("sbom_data_format_name", _known(data.get("spdxVersion")), "spdxVersion")
        put("sbom_data_format_version", _known(data.get("spdxVersion")), "spdxVersion")
        put("sbom_timestamp", _state(creation.get("created")), "creationInfo.created")
        put(
            "sbom_tool_name",
            _best(_state(c[5:]) for c in creators if isinstance(c, str) and c.startswith("Tool:")),
            "creationInfo.creators (Tool)",
        )
        put("sbom_version", None, "SPDX 2.3 has no document version field")
        put("sbom_author_signature", None, "SPDX 2.3 has no inline signature field")
        put(
            "sbom_tool_version",
            None,
            "creationInfo.creators Tool strings have no unambiguous version delimiter",
        )
        put(
            "sbom_generation_context",
            None,
            "creatorComment is free text; generation stage requires review",
        )
        put(
            "component_name",
            _every(packages, lambda p: _state(p.get("name"))),
            "all packages[].name",
        )
        put(
            "component_version",
            _every(packages, lambda p: _state(p.get("versionInfo"))),
            "all packages[].versionInfo",
        )
        put(
            "component_producer",
            _every(
                packages,
                lambda p: _best((_state(p.get("supplier")), _state(p.get("originator")))),
            ),
            "all packages[].supplier/originator",
        )
        put(
            "component_identifiers",
            _every(packages, _spdx2_identifier),
            "all packages[].externalRefs purl/cpe/swid/swh/gitoid or package-manager "
            "coordinates (not SPDXID)",
        )
        for key in ("component_hash_algorithm", "component_hash_value"):
            put(
                key,
                _every(packages, lambda p: _hash(p, spdx=True)),
                "all packages[].checksums (paired algorithm/value)",
            )
        put(
            "component_license",
            _every(
                packages,
                lambda p: _best(
                    (_state(p.get("licenseConcluded")), _state(p.get("licenseDeclared")))
                ),
            ),
            "all packages[].licenseConcluded/licenseDeclared",
        )
        put(
            "component_dependency_relationship",
            any(
                r.get("relationshipType") in _SPDX2_OPERATIONAL_RELATIONSHIPS
                and _known(r.get("spdxElementId"))
                and _known(r.get("relatedSpdxElement"))
                for r in _objects(data.get("relationships"))
            ),
            "relationships (runtime/provided dependency, link, prerequisite, containment; "
            "excludes build/dev/test/optional dependency and derivation)",
        )
    else:
        graph = _objects(data.get("@graph"))
        creation = next((e for e in graph if e.get("type") == "CreationInfo"), {})
        put("sbom_data_format_name", True, "@context SPDX 3")
        put("sbom_version", None, "SPDX 3 has no document version field")
        put(
            "sbom_data_format_version",
            _known(creation.get("specVersion")),
            "CreationInfo.specVersion",
        )
        put("sbom_timestamp", _state(creation.get("created")), "CreationInfo.created")
        put(
            "component_name",
            _every(components, lambda p: _state(p.get("name"))),
            "all graph Package elements[].name",
        )
        put(
            "component_identifiers",
            _every(components, _spdx3_identifier),
            "all graph Package elements[].software_packageUrl/externalIdentifier (not spdxId)",
        )
    return {
        "source": CISA_2026_SOURCE,
        "source_edition": "2026",
        "assessment": "presence_only",
        "mapping_authority": "project_interpretation",
        "compliance_status": "not_assessed",
        "elements": elements,
    }


def g7_ai_presence(
    data: dict[str, Any],
    fmt: str,
    components: list[dict[str, Any]],
    cisa: dict[str, Any],
    *,
    spdx3: bool = False,
) -> dict[str, Any]:
    models = [
        c
        for c in components
        if c.get("type") == "machine-learning-model" or "AIPackage" in str(c.get("type", ""))
    ]
    datasets = [
        c
        for c in components
        if c.get("type") == "data" or "DatasetPackage" in str(c.get("type", ""))
    ]
    if not models and not datasets:
        return {}
    clusters = {
        cluster: {key: _entry(None, "Semantic content requires manual review") for key in keys}
        for cluster, keys in G7_CLUSTERS.items()
    }
    for key in G7_CLUSTERS["metadata"][:-1]:
        clusters["metadata"][key] = dict(cisa["elements"][key])
    if fmt == "cyclonedx":
        # G7 includes inclusion AND derivation. CISA 2026 uses runtime dependencies.
        edge = any(
            _known(d.get("ref")) and any(_known(r) for r in _strings(d.get("dependsOn")))
            for d in _objects(data.get("dependencies"))
        )
        pedigree = any(
            _objects(_dict(c.get("pedigree")).get(k))
            for c in components
            for k in ("ancestors", "descendants", "variants")
        )
        clusters["metadata"]["sbom_dependency_relationship"] = _entry(
            edge or pedigree,
            "dependencies[] edge with known ref and dependsOn, or pedigree "
            "ancestors/descendants/variants (G7 interpretation)",
        )
        subject = _dict(_dict(data.get("metadata")).get("component"))
        for key, present, source in (
            ("system_name", _state(subject.get("name")), "metadata.component.name"),
            ("system_components", bool(components), "components including descendants"),
            ("system_producer", _producer(subject), "metadata.component.supplier/publisher/author"),
            ("system_version", _state(subject.get("version")), "metadata.component.version"),
        ):
            clusters["system"][key] = _entry(present, source)
        for cluster, prefix, objects in (
            ("models", "model", models),
            ("datasets", "dataset", datasets),
        ):
            fields: dict[str, Callable[[dict[str, Any]], bool | str]] = {
                "name": lambda c: _state(c.get("name")),
                "description": lambda c: _state(c.get("description")),
                "identifier": _cdx_identifier,
                "license": _license,
            }
            if prefix == "model":
                fields |= {
                    "version": lambda c: _state(c.get("version")),
                    "producer": _producer,
                    "hash_value": _hash,
                    "hash_algorithm": _hash,
                    "external_references": lambda c: any(
                        _known(r.get("url")) for r in _objects(c.get("externalReferences"))
                    ),
                }
            else:
                fields["hash"] = _hash
            for suffix, check in fields.items():
                clusters[cluster][prefix + "_" + suffix] = _entry(
                    _every(objects, check), f"all {prefix} components[].{suffix}"
                )
        clusters["security"]["vulnerability_referencing"] = _entry(
            any(_known(v.get("id")) for v in _objects(data.get("vulnerabilities"))),
            "vulnerabilities[].id",
        )
    elif spdx3:
        for cluster, keys in _G7_CDX_MAPPED.items():
            for key in keys:
                clusters[cluster][key] = _entry(UNSUPPORTED_MAPPING, "No supported field mapping")
        for cluster, prefix, objects in (
            ("models", "model", models),
            ("datasets", "dataset", datasets),
        ):
            clusters[cluster][prefix + "_name"] = _entry(
                _every(objects, lambda c: _state(c.get("name"))),
                f"all {prefix} graph elements[].name",
            )
            clusters[cluster][prefix + "_identifier"] = _entry(
                _every(objects, _spdx3_identifier),
                f"all {prefix} graph elements[].software_packageUrl/externalIdentifier",
            )
    return {
        "source": G7_AI_SOURCE,
        "source_date": "2026-05-12",
        "assessment": "presence_only",
        "mapping_authority": "project_interpretation",
        "compliance_status": "not_assessed",
        "clusters": clusters,
    }
