"""Croissant dataset metadata becomes `ai_training_data_lineage` evidence.

The AI catalog requires training-data lineage, and until now it could only
arrive as a free-schema manifest. Croissant (MLCommons) is the metadata
format dataset hubs publish, so a Croissant file dropped next to the other
artifacts now satisfies that evidence type, with the spec version recorded.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_croissant
from evidence_collector.parsers import parse_croissant
from evidence_collector.parsers._common import ParseError

_CROISSANT_11 = {
    "@context": {
        "@language": "en",
        "@vocab": "https://schema.org/",
        "cr": "http://mlcommons.org/croissant/",
        "dct": "http://purl.org/dc/terms/",
        "prov": "http://www.w3.org/ns/prov#",
        "odrl": "http://www.w3.org/ns/odrl/2/",
    },
    "@type": "sc:Dataset",
    "name": "support-tickets",
    "description": "Customer support tickets used to fine-tune the triage model.",
    "dct:conformsTo": ["http://mlcommons.org/croissant/1.1", "http://example.org/spec/0.1"],
    "license": ["https://spdx.org/licenses/CC-BY-4.0.html"],
    "url": "https://datasets.example.org/support-tickets",
    "version": "2.3.0",
    "datePublished": "2026-03-01",
    "creator": {"@type": "sc:Organization", "name": "Acme"},
    "prov:wasDerivedFrom": {"@id": "https://datasets.example.org/raw-tickets"},
    "prov:wasGeneratedBy": {"@id": "https://pipelines.example.org/dedup-run-42"},
    "usageInfo": {"@type": "odrl:Offer", "odrl:permission": {"odrl:action": "use"}},
    "distribution": [
        {"@type": "cr:FileObject", "@id": "tickets.parquet", "sha256": "ab" * 32},
        {"@type": "cr:FileObject", "@id": "labels.csv"},
    ],
    "recordSet": [{"@type": "cr:RecordSet", "name": "tickets"}],
}

_CROISSANT_10 = {
    "@context": {"@vocab": "https://schema.org/"},
    "@type": "sc:Dataset",
    "name": "minimal",
    "description": "Minimal Croissant 1.0 dataset.",
    "conformsTo": "http://mlcommons.org/croissant/1.0",
    "license": "https://creativecommons.org/licenses/by/4.0/",
    "url": "https://example.com/dataset/minimal",
    "distribution": [{"@type": "cr:FileObject", "@id": "minimal.csv"}],
    "recordSet": [{"@type": "cr:RecordSet", "name": "examples"}, {"@type": "cr:RecordSet"}],
}


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.09.24", commit_sha="abcdef1234567890")


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_croissant_11_file_is_read_with_its_version(tmp_path: Path) -> None:
    parsed = parse_croissant(_write(tmp_path / "tickets.croissant.json", _CROISSANT_11))

    assert parsed.croissant_version == "1.1"
    assert parsed.name == "support-tickets"
    assert parsed.dataset_version == "2.3.0"
    assert parsed.url == "https://datasets.example.org/support-tickets"
    assert parsed.licenses == ["https://spdx.org/licenses/CC-BY-4.0.html"]
    assert parsed.record_set_count == 1
    assert parsed.distribution_count == 2
    assert parsed.distribution_with_sha256 == 1
    assert parsed.provenance == ["wasDerivedFrom", "wasGeneratedBy"]
    assert parsed.has_usage_policy is True


def test_a_croissant_10_file_with_plain_keys_is_read(tmp_path: Path) -> None:
    parsed = parse_croissant(_write(tmp_path / "metadata.json", _CROISSANT_10))

    assert parsed.croissant_version == "1.0"
    assert parsed.licenses == ["https://creativecommons.org/licenses/by/4.0/"]
    assert parsed.record_set_count == 2
    assert parsed.provenance == []
    assert parsed.has_usage_policy is False


def test_a_json_file_that_is_not_croissant_is_rejected(tmp_path: Path) -> None:
    other = _write(
        tmp_path / "dataset.json", {"name": "x", "conformsTo": "https://example.org/other"}
    )
    with pytest.raises(ParseError):
        parse_croissant(other)


def test_the_evidence_is_training_data_lineage_for_the_dataset(tmp_path: Path) -> None:
    parsed = parse_croissant(_write(tmp_path / "tickets.croissant.json", _CROISSANT_11))
    evidence = normalize_croissant(parsed, _release())

    assert evidence.evidence_type == EvidenceType.AI_TRAINING_DATA_LINEAGE
    assert evidence.subject_type == SubjectType.AI_DATASET
    assert evidence.subject_ref == "https://datasets.example.org/support-tickets"
    assert evidence.status == EvidenceStatus.GENERATED
    assert evidence.metadata["croissant_version"] == "1.1"
    assert evidence.metadata["licenses"] == ["https://spdx.org/licenses/CC-BY-4.0.html"]
    assert evidence.metadata["provenance"] == ["wasDerivedFrom", "wasGeneratedBy"]
    assert "Croissant 1.1" in (evidence.summary or "")


def test_the_collector_picks_croissant_up_from_the_artifacts_dir(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "metadata.json", _CROISSANT_10)
    _write(artifacts / "unrelated.json", {"hello": "world"})

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    lineage = [
        e for e in report.evidence if e.evidence_type == EvidenceType.AI_TRAINING_DATA_LINEAGE
    ]
    assert len(lineage) == 1
    assert lineage[0].metadata["croissant_version"] == "1.0"


def test_croissant_alone_meets_the_ai_catalog_lineage_control(tmp_path: Path) -> None:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.controls.catalog import bundled_catalog_path
    from evidence_collector.domain.models import Application

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "tickets.croissant.json", _CROISSANT_11)

    result = run_pipeline(
        Application(name="triage-model", repository="acme/triage-model"),
        _release(),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
        catalog_path=bundled_catalog_path("catalog-ai.yaml"),
    )
    assert result.json_path is not None
    bundle = json.loads(result.json_path.read_text(encoding="utf-8"))
    [lineage] = [
        e for e in bundle["control_evaluations"] if e["control_id"] == "AI-TRAINING-LINEAGE"
    ]
    assert lineage["evaluation_status"] == "met"


def test_oversized_name_and_url_are_clipped_not_rejected(tmp_path: Path) -> None:
    """Hub metadata is untrusted input; a long field must not cost the evidence."""
    doc = dict(_CROISSANT_10, name="N" * 1500, url="https://example.org/" + "u" * 600)
    parsed = parse_croissant(_write(tmp_path / "big.json", doc))
    evidence = normalize_croissant(parsed, _release())

    assert len(evidence.subject_ref) <= 500
    assert len(evidence.summary or "") <= 1000
    assert evidence.metadata["dataset_name"] == "N" * 1500


@pytest.mark.parametrize(
    "conforms_to",
    ["http://mlcommons.org/croissant/2.0", "http://mlcommons.org/croissant/not-a-version"],
)
def test_an_unsupported_croissant_version_is_not_read(tmp_path: Path, conforms_to: str) -> None:
    """Only 1.0 and 1.1 are implemented; anything else must not satisfy the control."""
    doc = dict(_CROISSANT_10, conformsTo=conforms_to)
    with pytest.raises(ParseError):
        parse_croissant(_write(tmp_path / "future.json", doc))

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "future.json", doc)
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [
        e for e in report.evidence if e.evidence_type == EvidenceType.AI_TRAINING_DATA_LINEAGE
    ] == []


def test_a_supported_version_later_in_the_list_is_found(tmp_path: Path) -> None:
    doc = dict(
        _CROISSANT_10,
        conformsTo=["http://mlcommons.org/croissant/2.0", "http://mlcommons.org/croissant/1.1"],
    )
    assert parse_croissant(_write(tmp_path / "multi.json", doc)).croissant_version == "1.1"


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        (1, "1"),
        (0, "0"),
        (2.5, "2.5"),
        # Valid JSON, but too large for a float: it must not abort the run.
        pytest.param(10**400, str(10**400), id="int-beyond-float-range"),
    ],
)
def test_a_numeric_version_is_kept_as_text(
    tmp_path: Path, version: int | float, expected: str
) -> None:
    """schema.org `version` is Number or Text; Kaggle and OpenML publish `"version": 1`."""
    parsed = parse_croissant(
        _write(tmp_path / "metadata.json", dict(_CROISSANT_10, version=version))
    )

    assert parsed.dataset_version == expected
    assert normalize_croissant(parsed, _release()).metadata["dataset_version"] == expected


@pytest.mark.parametrize("version", [True, float("nan"), float("inf")])
def test_a_boolean_or_non_finite_number_is_not_a_version(tmp_path: Path, version: object) -> None:
    """`json` reads the literals NaN and Infinity; neither is a version, nor is a bool."""
    parsed = parse_croissant(
        _write(tmp_path / "metadata.json", dict(_CROISSANT_10, version=version))
    )

    assert parsed.dataset_version is None


_MULTILINGUAL_CONTEXT = {
    "@language": "en",
    "@vocab": "https://schema.org/",
    "name": {"@container": "@language"},
}


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        # The shape of the MLCommons 1.1 minimal_multilingual recipe.
        ({"de": "Beispiel", "en": "example", "fr": "exemple"}, "example"),
        ({"de": "Beispiel", "@none": "untagged"}, "untagged"),
        ({"fr": "exemple", "de": "Beispiel"}, "Beispiel"),
        ({"en": ["first", "second"]}, "first"),
        ({"@value": "tagged", "@language": "en"}, "tagged"),
        ({"@value": "plain"}, "plain"),
        ([{"@value": "one", "@language": "de"}, {"@value": "two", "@language": "en"}], "one"),
        (["", {"@value": " "}, "third"], "third"),
    ],
)
def test_a_language_tagged_name_is_read(tmp_path: Path, name: object, expected: str) -> None:
    doc = dict(_CROISSANT_10, name=name)
    doc["@context"] = _MULTILINGUAL_CONTEXT
    parsed = parse_croissant(_write(tmp_path / "metadata.json", doc))
    evidence = normalize_croissant(parsed, _release())

    assert parsed.name == expected
    assert evidence.metadata["dataset_name"] == expected
    assert evidence.confidence == ConfidenceLevel.HIGH
    assert evidence.summary == f"Croissant 1.0 metadata for dataset {expected}"


def test_a_license_object_is_still_read_by_its_url(tmp_path: Path) -> None:
    """Kaggle publishes the license as a CreativeWork object with a name and url."""
    license_object = {
        "@type": "sc:CreativeWork",
        "name": "CC0: Public Domain",
        "url": "https://creativecommons.org/publicdomain/zero/1.0/",
    }
    parsed = parse_croissant(
        _write(tmp_path / "metadata.json", dict(_CROISSANT_10, license=license_object))
    )

    assert parsed.licenses == ["https://creativecommons.org/publicdomain/zero/1.0/"]


@pytest.mark.parametrize("placeholder", ["unknown", "Unknown", "NOASSERTION", "none"])
def test_a_placeholder_license_does_not_raise_confidence(tmp_path: Path, placeholder: str) -> None:
    """The MLCommons gpt-3 1.0 file declares `"license": "unknown"`: no license is named."""
    parsed = parse_croissant(
        _write(tmp_path / "metadata.json", dict(_CROISSANT_10, license=placeholder))
    )
    evidence = normalize_croissant(parsed, _release())

    assert evidence.confidence == ConfidenceLevel.MEDIUM
    assert evidence.metadata["licenses"] == [placeholder]


@pytest.mark.parametrize(
    "license_value", ["other", ["unknown", "https://spdx.org/licenses/CC-BY-4.0.html"]]
)
def test_a_real_license_still_counts_next_to_a_placeholder(
    tmp_path: Path, license_value: object
) -> None:
    """Hubs use `other` for a real custom license, so it names one."""
    parsed = parse_croissant(
        _write(tmp_path / "metadata.json", dict(_CROISSANT_10, license=license_value))
    )

    assert normalize_croissant(parsed, _release()).confidence == ConfidenceLevel.HIGH


@pytest.mark.parametrize("name", ["model-card.json", "lm-eval.json", "dataset.garak.json"])
def test_croissant_wins_over_a_reserved_file_name(tmp_path: Path, name: str) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / name, _CROISSANT_10)

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert report.errors == []
    assert [e.evidence_type for e in report.evidence] == [EvidenceType.AI_TRAINING_DATA_LINEAGE]
