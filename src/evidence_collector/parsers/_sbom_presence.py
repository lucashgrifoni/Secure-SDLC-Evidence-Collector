"""Bounded presence maps for CISA 2026 and the voluntary G7 AI SBOM guidance.

These are project interpretations of explicit input fields, not schema,
signature, applicability, accuracy, or regulatory compliance verification.
"""

from __future__ import annotations

from collections.abc import Callable
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
_UNKNOWN = {"", "NONE", "NOASSERTION", "UNKNOWN", "N/A", "NULL"}


def _known(value: Any) -> bool:
    return isinstance(value, str) and value.strip().upper() not in _UNKNOWN


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _objects(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _every(objects: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> bool:
    return bool(objects) and all(predicate(obj) for obj in objects)


def _entry(present: bool | None, source: str) -> dict[str, str]:
    return {
        "status": "not_machine_checkable"
        if present is None
        else "present"
        if present
        else "absent",
        "source": source,
    }


def _hash(c: dict[str, Any], *, spdx: bool = False) -> bool:
    return any(
        _known(h.get("algorithm" if spdx else "alg"))
        and _known(h.get("checksumValue" if spdx else "content"))
        for h in _objects(c.get("checksums" if spdx else "hashes"))
    )


def _producer(c: dict[str, Any]) -> bool:
    return (
        _known(_dict(c.get("supplier")).get("name"))
        or _known(c.get("publisher"))
        or _known(c.get("author"))
    )


def _license(c: dict[str, Any]) -> bool:
    return any(
        _known(license_entry.get("expression"))
        or _known(_dict(license_entry.get("license")).get("id"))
        or _known(_dict(license_entry.get("license")).get("name"))
        for license_entry in _objects(c.get("licenses"))
    )


def _cdx_relationships(data: dict[str, Any], components: list[dict[str, Any]]) -> bool:
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
    elements = {k: _entry(None, "No supported field mapping") for k in CISA_2026_KEYS}

    def put(key: str, value: bool | None, source: str) -> None:
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
            any(_known(a.get("name")) for a in _objects(meta.get("authors"))),
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
        put("sbom_timestamp", _known(meta.get("timestamp")), "metadata.timestamp")
        put(
            "sbom_author_signature",
            None if data.get("signature") else False,
            "signature (author identity and cryptography require verification)",
        )
        put(
            "sbom_tool_name",
            _every(tool_objects, lambda t: _known(t.get("name"))),
            "metadata.tools",
        )
        put(
            "sbom_tool_version",
            _every(tool_objects, lambda t: _known(t.get("name")) and _known(t.get("version"))),
            "metadata.tools[].version",
        )
        put(
            "sbom_generation_context",
            any(
                _known(lifecycle.get("phase")) or _known(lifecycle.get("name"))
                for lifecycle in _objects(meta.get("lifecycles"))
            ),
            "metadata.lifecycles",
        )
        put(
            "component_name",
            _every(components, lambda c: _known(c.get("name"))),
            "all components[].name, including subject and descendants",
        )
        put(
            "component_version",
            _every(components, lambda c: _known(c.get("version"))),
            "all components[].version",
        )
        put(
            "component_producer",
            _every(components, _producer),
            "all components[].supplier.name/publisher/author",
        )
        put(
            "component_identifiers",
            _every(components, lambda c: any(_known(c.get(k)) for k in ("bom-ref", "purl", "cpe"))),
            "all components[].bom-ref/purl/cpe",
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
            any(
                isinstance(c, str)
                and c.startswith(("Person:", "Organization:"))
                and _known(c.split(":", 1)[1])
                for c in creators
            ),
            "creationInfo.creators (Person/Organization)",
        )
        put("sbom_data_format_name", _known(data.get("spdxVersion")), "spdxVersion")
        put("sbom_data_format_version", _known(data.get("spdxVersion")), "spdxVersion")
        put("sbom_timestamp", _known(creation.get("created")), "creationInfo.created")
        put(
            "sbom_tool_name",
            any(isinstance(c, str) and c.startswith("Tool:") and _known(c[5:]) for c in creators),
            "creationInfo.creators (Tool)",
        )
        # Tool strings do not define an unambiguous version delimiter.
        put(
            "sbom_generation_context",
            None,
            "creatorComment is free text; generation stage requires review",
        )
        put(
            "component_name",
            _every(packages, lambda p: _known(p.get("name"))),
            "all packages[].name",
        )
        put(
            "component_version",
            _every(packages, lambda p: _known(p.get("versionInfo"))),
            "all packages[].versionInfo",
        )
        put(
            "component_producer",
            _every(packages, lambda p: _known(p.get("supplier")) or _known(p.get("originator"))),
            "all packages[].supplier/originator",
        )
        put(
            "component_identifiers",
            _every(packages, lambda p: _known(p.get("SPDXID"))),
            "all packages[].SPDXID",
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
                lambda p: _known(p.get("licenseConcluded")) or _known(p.get("licenseDeclared")),
            ),
            "all packages[].licenseConcluded/licenseDeclared",
        )
        put(
            "component_dependency_relationship",
            any(
                r.get("relationshipType")
                in {"DEPENDS_ON", "DEPENDENCY_OF", "CONTAINS", "CONTAINED_BY"}
                and _known(r.get("spdxElementId"))
                and _known(r.get("relatedSpdxElement"))
                for r in _objects(data.get("relationships"))
            ),
            "relationships (runtime dependency/containment; excludes derivation)",
        )
    else:
        graph = _objects(data.get("@graph"))
        creation = next((e for e in graph if e.get("type") == "CreationInfo"), {})
        put("sbom_data_format_name", True, "@context SPDX 3")
        put(
            "sbom_data_format_version",
            _known(creation.get("specVersion")),
            "CreationInfo.specVersion",
        )
        put("sbom_timestamp", _known(creation.get("created")), "CreationInfo.created")
        put(
            "component_name",
            _every(components, lambda p: _known(p.get("name"))),
            "all graph Package elements[].name",
        )
        put(
            "component_identifiers",
            _every(components, lambda p: _known(p.get("spdxId"))),
            "all graph Package elements[].spdxId",
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
        cluster: {
            key: _entry(
                None, "Semantic content requires manual review or an unsupported format mapping"
            )
            for key in keys
        }
        for cluster, keys in G7_CLUSTERS.items()
    }
    for key in G7_CLUSTERS["metadata"][:-1]:
        clusters["metadata"][key] = dict(cisa["elements"][key])
    if fmt == "cyclonedx":
        # G7 includes inclusion AND derivation. CISA 2026 uses runtime dependencies.
        dependencies = _objects(data.get("dependencies"))
        pedigree = any(_dict(c.get("pedigree")) for c in components)
        clusters["metadata"]["sbom_dependency_relationship"] = _entry(
            bool(dependencies) or pedigree, "dependencies/pedigree (G7 interpretation)"
        )
        subject = _dict(_dict(data.get("metadata")).get("component"))
        for key, present, source in (
            ("system_name", _known(subject.get("name")), "metadata.component.name"),
            ("system_components", bool(components), "components including descendants"),
            ("system_producer", _producer(subject), "metadata.component.supplier/publisher/author"),
            ("system_version", _known(subject.get("version")), "metadata.component.version"),
        ):
            clusters["system"][key] = _entry(present, source)
        for cluster, prefix, objects in (
            ("models", "model", models),
            ("datasets", "dataset", datasets),
        ):
            fields = {
                "name": lambda c: _known(c.get("name")),
                "description": lambda c: _known(c.get("description")),
                "identifier": lambda c: any(_known(c.get(k)) for k in ("bom-ref", "purl", "cpe")),
                "license": _license,
            }
            if prefix == "model":
                fields |= {
                    "version": lambda c: _known(c.get("version")),
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
        for cluster, prefix, objects in (
            ("models", "model", models),
            ("datasets", "dataset", datasets),
        ):
            for suffix, field in (("name", "name"), ("identifier", "spdxId")):
                clusters[cluster][prefix + "_" + suffix] = _entry(
                    bool(objects) and all(_known(c.get(field)) for c in objects),
                    f"all {prefix} graph elements[].{field}",
                )
    return {
        "source": G7_AI_SOURCE,
        "source_date": "2026-05-12",
        "assessment": "presence_only",
        "mapping_authority": "project_interpretation",
        "compliance_status": "not_assessed",
        "clusters": clusters,
    }
