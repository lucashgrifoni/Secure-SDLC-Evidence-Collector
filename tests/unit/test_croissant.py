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
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType, SubjectType
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
