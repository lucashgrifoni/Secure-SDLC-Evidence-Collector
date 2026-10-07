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
    assert result["elements"]["sbom_author_signature"]["status"] == "absent"


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
    assert result["component_producer"]["status"] == "absent"
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
    assert result["component_producer"]["status"] == "absent"
    assert result["component_license"]["status"] == "absent"
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
