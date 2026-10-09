"""Content-derived CISA 2026 and G7 AI presence maps, without compliance claims."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sbom
from evidence_collector.parsers.sbom import parse_sbom


def parse(tmp_path: Path, data: dict[str, Any]):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return parse_sbom(path)


def cdx() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 2,
        "metadata": {
            "timestamp": "2026-10-07T00:00:00Z",
            "authors": [{"name": "SBOM Operator"}],
            "tools": {"components": [{"name": "fixture", "version": "1.0"}]},
            "lifecycles": [{"phase": "build"}],
        },
        "components": [
            {
                "type": "machine-learning-model",
                "name": "classifier",
                "version": "1",
                "bom-ref": "model",
                "supplier": {"name": "Model Producer"},
                "description": "Synthetic classifier.",
                "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            }
        ],
        "dependencies": [{"ref": "model", "dependsOn": []}],
    }


def test_all_17_elements_are_recorded_with_bounded_claims(tmp_path: Path) -> None:
    parsed = parse(tmp_path, cdx())
    result = parsed.cisa_2026_presence
    assert len(result["elements"]) == 17
    assert result["assessment"] == "presence_only"
    assert result["compliance_status"] == "not_assessed"
    assert result["elements"]["sbom_version"]["status"] == "present"
    assert result["elements"]["component_hash_algorithm"]["status"] == "present"
    assert result["elements"]["sbom_author_signature"]["status"] == "not_machine_checkable"


def test_tool_cannot_stand_in_for_the_sbom_author(tmp_path: Path) -> None:
    data = cdx()
    del data["metadata"]["authors"]
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["sbom_author"]["status"] == "absent"
    assert result["sbom_tool_name"]["status"] == "present"


@pytest.mark.parametrize("path", ["alg", "content"])
def test_hash_algorithm_and_value_must_share_a_record(tmp_path: Path, path: str) -> None:
    data = cdx()
    data["components"][0]["hashes"] = [{"alg": "SHA-256"}, {"content": "a" * 64}]
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert (
        result["component_hash_" + ("algorithm" if path == "alg" else "value")]["status"]
        == "absent"
    )


def test_nested_subject_unknown_producer_is_not_hidden(tmp_path: Path) -> None:
    data = cdx()
    data["metadata"]["component"] = copy.deepcopy(data["components"][0])
    data["metadata"]["component"]["components"] = [
        {"type": "library", "name": "nested", "version": "1", "supplier": {"name": "NOASSERTION"}}
    ]
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["component_producer"]["status"] == "declared_unknown"
    assert result["component_hash_value"]["status"] == "absent"


def test_version_is_not_invented_and_generic_signature_is_not_author_proof(tmp_path: Path) -> None:
    data = cdx()
    del data["version"]
    data["signature"] = {"algorithm": "RS256", "value": "synthetic"}
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["sbom_version"]["status"] == "absent"
    assert result["sbom_author_signature"]["status"] == "not_machine_checkable"


def test_g7_has_50_elements_in_seven_clusters_only_for_ai(tmp_path: Path) -> None:
    parsed = parse(tmp_path, cdx())
    result = parsed.g7_ai_presence
    assert result["assessment"] == "presence_only"
    assert result["mapping_authority"] == "project_interpretation"
    assert len(result["clusters"]) == 7
    assert sum(len(v) for v in result["clusters"].values()) == 50
    assert result["clusters"]["models"]["model_name"]["status"] == "present"
    assert (
        result["clusters"]["models"]["model_training_properties"]["status"]
        == "not_machine_checkable"
    )
    plain = cdx()
    plain["components"][0]["type"] = "library"
    assert parse(tmp_path, plain).g7_ai_presence == {}


def test_spdx2_placeholders_and_derived_from_are_not_runtime_dependencies(tmp_path: Path) -> None:
    data = {
        "spdxVersion": "SPDX-2.3",
        "name": "demo",
        "creationInfo": {"created": "2026-10-07T00:00:00Z", "creators": ["Tool: fixture-1"]},
        "packages": [
            {
                "SPDXID": "SPDXRef-model",
                "name": "model",
                "versionInfo": "1",
                "supplier": "NOASSERTION",
                "licenseConcluded": "NONE",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-model",
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": "SPDXRef-source",
            }
        ],
    }
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["sbom_author"]["status"] == "absent"
    assert result["component_producer"]["status"] == "declared_unknown"
    assert result["component_license"]["status"] == "declared_unknown"
    assert result["component_dependency_relationship"]["status"] == "absent"
    assert result["sbom_version"]["status"] == "not_machine_checkable"
    assert result["sbom_tool_version"]["status"] == "not_machine_checkable"


def test_spdx3_does_not_invent_unsupported_document_version(tmp_path: Path) -> None:
    data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"type": "CreationInfo", "specVersion": "3.0.1", "created": "2026-10-07T00:00:00Z"},
            {"type": "ai_AIPackage", "spdxId": "urn:model", "name": "model"},
        ],
    }
    parsed = parse(tmp_path, data)
    assert len(parsed.cisa_2026_presence["elements"]) == 17
    assert (
        parsed.cisa_2026_presence["elements"]["sbom_version"]["status"] == "not_machine_checkable"
    )
    assert parsed.g7_ai_presence["clusters"]["models"]["model_name"]["status"] == "present"


def test_normalization_keeps_legacy_metadata_and_propagates_new_maps(tmp_path: Path) -> None:
    parsed = parse(tmp_path, cdx())
    ev = normalize_sbom(
        parsed, ReleaseContext(release_id="1", commit_sha="abcdef1234567890", branch="main")
    )
    assert "cisa_2025_minimum_elements" in ev.metadata
    assert ev.metadata["cisa_2026_presence"] == parsed.cisa_2026_presence
    assert ev.metadata["g7_ai_presence"] == parsed.g7_ai_presence


def spdx2(**package: Any) -> dict[str, Any]:
    pkg = {"SPDXID": "SPDXRef-pkg", "name": "pkg", "versionInfo": "1", **package}
    return {
        "spdxVersion": "SPDX-2.3",
        "name": "demo",
        "creationInfo": {"created": "2026-10-07T00:00:00Z", "creators": ["Tool: fixture-1"]},
        "packages": [pkg],
    }


def test_document_local_bom_ref_is_not_a_component_identifier(tmp_path: Path) -> None:
    parsed = parse(tmp_path, cdx())
    assert parsed.cisa_2026_presence["elements"]["component_identifiers"]["status"] == "absent"
    assert parsed.g7_ai_presence["clusters"]["models"]["model_identifier"]["status"] == "absent"


@pytest.mark.parametrize(
    "field",
    [
        {"purl": "pkg:huggingface/acme/classifier@1"},
        {"cpe": "cpe:2.3:a:acme:classifier:1:*:*:*:*:*:*:*"},
        {"swid": {"tagId": "acme-classifier-1", "name": "classifier"}},
        {"swhid": ["swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2"]},
        {"omniborId": ["gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64"]},
    ],
)
def test_lookup_identifiers_named_by_cisa_count(tmp_path: Path, field: dict[str, Any]) -> None:
    data = cdx()
    data["components"][0].update(field)
    parsed = parse(tmp_path, data)
    assert parsed.cisa_2026_presence["elements"]["component_identifiers"]["status"] == "present"
    assert parsed.g7_ai_presence["clusters"]["models"]["model_identifier"]["status"] == "present"


def test_spdx2_spdxid_alone_is_not_a_component_identifier(tmp_path: Path) -> None:
    result = parse(tmp_path, spdx2()).cisa_2026_presence["elements"]
    assert result["component_identifiers"]["status"] == "absent"


@pytest.mark.parametrize(
    ("category", "ref_type", "locator", "status"),
    [
        ("PACKAGE-MANAGER", "purl", "pkg:pypi/pkg@1", "present"),
        ("SECURITY", "cpe23Type", "cpe:2.3:a:acme:pkg:1:*:*:*:*:*:*:*", "present"),
        ("PERSISTENT-ID", "swh", "swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2", "present"),
        (
            "PERSISTENT_ID",
            "gitoid",
            "gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64",
            "present",
        ),
        ("SECURITY", "advisory", "https://example.invalid/advisory", "absent"),
    ],
)
def test_spdx2_external_identifier_refs(
    tmp_path: Path, category: str, ref_type: str, locator: str, status: str
) -> None:
    ref = {"referenceCategory": category, "referenceType": ref_type, "referenceLocator": locator}
    result = parse(tmp_path, spdx2(externalRefs=[ref])).cisa_2026_presence["elements"]
    assert result["component_identifiers"]["status"] == status


@pytest.mark.parametrize(
    ("relationship", "status"),
    [
        ("RUNTIME_DEPENDENCY_OF", "present"),
        ("STATIC_LINK", "present"),
        ("DYNAMIC_LINK", "present"),
        ("HAS_PREREQUISITE", "present"),
        ("PROVIDED_DEPENDENCY_OF", "present"),
        ("DEPENDS_ON", "present"),
        ("BUILD_DEPENDENCY_OF", "absent"),
        ("TEST_DEPENDENCY_OF", "absent"),
        ("DEV_DEPENDENCY_OF", "absent"),
        ("OPTIONAL_DEPENDENCY_OF", "absent"),
        ("DESCENDANT_OF", "absent"),
        ("DESCRIBES", "absent"),
    ],
)
def test_spdx2_operational_dependency_relationship_types(
    tmp_path: Path, relationship: str, status: str
) -> None:
    data = spdx2()
    data["relationships"] = [
        {
            "spdxElementId": "SPDXRef-lib",
            "relationshipType": relationship,
            "relatedSpdxElement": "SPDXRef-pkg",
        }
    ]
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["component_dependency_relationship"]["status"] == status


@pytest.mark.parametrize("marker", ["NOASSERTION", "NONE", "UNKNOWN", " unknown "])
def test_explicit_unknown_is_distinct_from_a_missing_field(tmp_path: Path, marker: str) -> None:
    declared = parse(tmp_path, spdx2(supplier=marker)).cisa_2026_presence["elements"]
    missing = parse(tmp_path, spdx2()).cisa_2026_presence["elements"]
    assert declared["component_producer"]["status"] == "declared_unknown"
    assert missing["component_producer"]["status"] == "absent"


def test_one_missing_component_outranks_a_declared_unknown(tmp_path: Path) -> None:
    data = cdx()
    data["components"][0]["supplier"] = {"name": "UNKNOWN"}
    data["components"].append({"type": "library", "name": "lib", "version": "1"})
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["component_producer"]["status"] == "absent"
    del data["components"][1]
    result = parse(tmp_path, data).cisa_2026_presence["elements"]
    assert result["component_producer"]["status"] == "declared_unknown"


def test_missing_inline_signature_is_not_reported_as_absent(tmp_path: Path) -> None:
    cdx_sig = parse(tmp_path, cdx()).cisa_2026_presence["elements"]["sbom_author_signature"]
    spdx_sig = parse(tmp_path, spdx2()).cisa_2026_presence["elements"]["sbom_author_signature"]
    assert cdx_sig["status"] == "not_machine_checkable"
    assert "detached" in cdx_sig["source"]
    assert spdx_sig["status"] == "not_machine_checkable"


def test_spdx3_unimplemented_mappings_are_not_called_uncheckable(tmp_path: Path) -> None:
    data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"type": "CreationInfo", "specVersion": "3.0.1", "created": "2026-10-07T00:00:00Z"},
            {"type": "ai_AIPackage", "spdxId": "urn:model", "name": "model"},
        ],
    }
    parsed = parse(tmp_path, data)
    elements = parsed.cisa_2026_presence["elements"]
    for key in ("sbom_author", "sbom_tool_name", "component_version", "component_hash_value"):
        assert elements[key]["status"] == "unsupported_mapping"
    assert elements["sbom_version"]["status"] == "not_machine_checkable"
    assert elements["component_identifiers"]["status"] == "absent"
    models = parsed.g7_ai_presence["clusters"]["models"]
    assert models["model_version"]["status"] == "unsupported_mapping"
    assert models["model_identifier"]["status"] == "absent"
    assert models["model_training_properties"]["status"] == "not_machine_checkable"


def test_spdx3_external_identifier_counts(tmp_path: Path) -> None:
    data = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {"type": "CreationInfo", "specVersion": "3.0.1", "created": "2026-10-07T00:00:00Z"},
            {
                "type": "ai_AIPackage",
                "spdxId": "urn:model",
                "name": "model",
                "externalIdentifier": [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "packageUrl",
                        "identifier": "pkg:huggingface/acme/model@1",
                    }
                ],
            },
        ],
    }
    parsed = parse(tmp_path, data)
    assert parsed.cisa_2026_presence["elements"]["component_identifiers"]["status"] == "present"
    assert parsed.g7_ai_presence["clusters"]["models"]["model_identifier"]["status"] == "present"


@pytest.mark.parametrize(
    "dependencies", [[{}], [{"ref": "model"}], [{"ref": "model", "dependsOn": []}]]
)
def test_g7_dependency_relationship_needs_a_real_edge(
    tmp_path: Path, dependencies: list[dict[str, Any]]
) -> None:
    data = cdx()
    data["dependencies"] = dependencies
    metadata = parse(tmp_path, data).g7_ai_presence["clusters"]["metadata"]
    assert metadata["sbom_dependency_relationship"]["status"] == "absent"


def test_g7_dependency_relationship_accepts_an_edge_or_pedigree(tmp_path: Path) -> None:
    data = cdx()
    data["dependencies"] = [{"ref": "model", "dependsOn": ["dataset"]}]
    metadata = parse(tmp_path, data).g7_ai_presence["clusters"]["metadata"]
    assert metadata["sbom_dependency_relationship"]["status"] == "present"
    data = cdx()
    data["components"][0]["pedigree"] = {"ancestors": [{"name": "base-model"}]}
    metadata = parse(tmp_path, data).g7_ai_presence["clusters"]["metadata"]
    assert metadata["sbom_dependency_relationship"]["status"] == "present"


def test_every_emitted_status_is_in_the_documented_vocabulary(tmp_path: Path) -> None:
    from evidence_collector.parsers._sbom_presence import PRESENCE_STATES

    doc = Path("docs/evidence-profile-migration.md").read_text(encoding="utf-8")
    for state in PRESENCE_STATES:
        assert f"`{state}`" in doc
    parsed = parse(tmp_path, cdx())
    statuses = {e["status"] for e in parsed.cisa_2026_presence["elements"].values()}
    statuses |= {
        e["status"] for c in parsed.g7_ai_presence["clusters"].values() for e in c.values()
    }
    assert statuses <= set(PRESENCE_STATES)


def test_migration_doc_names_the_metadata_keys_the_engine_emits(tmp_path: Path) -> None:
    parsed = parse(tmp_path, cdx())
    ev = normalize_sbom(
        parsed, ReleaseContext(release_id="1", commit_sha="abcdef1234567890", branch="main")
    )
    doc = Path("docs/evidence-profile-migration.md").read_text(encoding="utf-8")
    for key in ("cisa_2026_presence", "g7_ai_presence"):
        assert key in ev.metadata
        assert f"`metadata.{key}" in doc
    assert "cisa_2026_minimum_elements" not in doc
    assert "g7_2026_ai_minimum_elements" not in doc
