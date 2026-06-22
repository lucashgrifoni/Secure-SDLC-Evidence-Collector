"""Tests for the SLSA build-provenance parser + normalizer.

Covers the three envelopes (raw in-toto Statement, DSSE envelope, Sigstore
bundle), SLSA Provenance v1 and v0.2 field layouts, JSONL loading, the
rejection of non-provenance / incomplete attestations, the DSSE decode
defenses, the normalizer output, and end-to-end detection through the local
artifact collector.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_provenance
from evidence_collector.parsers import parse_provenance
from evidence_collector.parsers._common import ParseError

_PROV_V1 = "https://slsa.dev/provenance/v1"
_BUILDER = "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


def _statement_v1(**predicate_overrides: Any) -> dict[str, Any]:
    predicate: dict[str, Any] = {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {"workflow": {"repository": "https://github.com/acme/app"}},
        },
        "runDetails": {
            "builder": {"id": _BUILDER},
            "metadata": {"invocationId": "https://github.com/acme/app/actions/runs/123"},
        },
    }
    predicate.update(predicate_overrides)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pkg:pypi/demo@1.0.0", "digest": {"sha256": "deadbeef"}}],
        "predicateType": _PROV_V1,
        "predicate": predicate,
    }


def _dsse(statement: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload,
        "signatures": [{"sig": "MEUCIQ..."}],
    }


def _bundle(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"x509CertificateChain": {"certificates": []}},
        "dsseEnvelope": _dsse(statement),
    }


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "prov.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_raw_statement_v1(tmp_path: Path) -> None:
    parsed = parse_provenance(_write(tmp_path, _statement_v1()))
    assert parsed.predicate_type == _PROV_V1
    assert parsed.builder_id == _BUILDER
    assert parsed.build_type == "https://actions.github.io/buildtypes/workflow/v1"
    assert parsed.subject_name == "pkg:pypi/demo@1.0.0"
    assert parsed.invocation_id == "https://github.com/acme/app/actions/runs/123"
    assert parsed.source_repository == "https://github.com/acme/app"
    assert parsed.envelope == "statement"


def test_parse_provenance_v0_2_layout(tmp_path: Path) -> None:
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "blob", "digest": {"sha256": "x"}}],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {"id": "https://example.com/builder"},
            "buildType": "https://example.com/buildtype",
            "metadata": {"invocationId": "inv-42"},
        },
    }
    parsed = parse_provenance(_write(tmp_path, statement))
    assert parsed.builder_id == "https://example.com/builder"
    assert parsed.build_type == "https://example.com/buildtype"
    assert parsed.invocation_id == "inv-42"
    assert parsed.source_repository is None


def test_parse_dsse_envelope(tmp_path: Path) -> None:
    parsed = parse_provenance(_write(tmp_path, _dsse(_statement_v1())))
    assert parsed.envelope == "dsse"
    assert parsed.builder_id == _BUILDER


def test_parse_sigstore_bundle(tmp_path: Path) -> None:
    parsed = parse_provenance(_write(tmp_path, _bundle(_statement_v1())))
    assert parsed.envelope == "sigstore-bundle"
    assert parsed.builder_id == _BUILDER


def test_parse_jsonl_first_record(tmp_path: Path) -> None:
    target = tmp_path / "attestations.jsonl"
    lines = [json.dumps(_bundle(_statement_v1())), json.dumps(_bundle(_statement_v1()))]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    parsed = parse_provenance(target)
    assert parsed.builder_id == _BUILDER
    assert parsed.envelope == "sigstore-bundle"


def test_parse_rejects_non_provenance_predicate(tmp_path: Path) -> None:
    statement = _statement_v1()
    statement["predicateType"] = "https://slsa.dev/verification_summary/v1"
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, statement))


def test_parse_rejects_unrecognized_shape(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, {"foo": "bar"}))


def test_parse_rejects_missing_predicate(tmp_path: Path) -> None:
    statement = _statement_v1()
    statement["predicate"] = "nope"
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, statement))


def test_parse_rejects_missing_builder_id(tmp_path: Path) -> None:
    statement = _statement_v1(runDetails={"metadata": {"invocationId": "x"}})
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, statement))


def test_parse_rejects_missing_build_type(tmp_path: Path) -> None:
    statement = _statement_v1(buildDefinition={"externalParameters": {}})
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, statement))


def test_parse_rejects_dsse_with_non_string_payload(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_provenance(
            _write(tmp_path, {"payloadType": "application/vnd.in-toto+json", "payload": 123})
        )


def test_parse_rejects_dsse_with_bad_base64(tmp_path: Path) -> None:
    bad = {"payloadType": "application/vnd.in-toto+json", "payload": "!!!not-base64!!!"}
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, bad))


def test_parse_rejects_dsse_payload_not_an_object(tmp_path: Path) -> None:
    payload = base64.b64encode(json.dumps(["not", "an", "object"]).encode()).decode("ascii")
    with pytest.raises(ParseError):
        parse_provenance(
            _write(tmp_path, {"payloadType": "application/vnd.in-toto+json", "payload": payload})
        )


def test_parse_rejects_non_json_non_jsonl(tmp_path: Path) -> None:
    target = tmp_path / "garbage.json"
    target.write_text("this is not json at all", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_provenance(target)


def test_parse_subject_missing_yields_none(tmp_path: Path) -> None:
    statement = _statement_v1()
    statement["subject"] = "not-a-list"
    parsed = parse_provenance(_write(tmp_path, statement))
    assert parsed.subject_name is None


def test_parse_subject_skips_malformed_then_picks_valid(tmp_path: Path) -> None:
    statement = _statement_v1()
    statement["subject"] = ["not-a-dict", {"name": ""}, {"name": "real-subject"}]
    parsed = parse_provenance(_write(tmp_path, statement))
    assert parsed.subject_name == "real-subject"


def test_parse_subject_all_malformed_yields_none(tmp_path: Path) -> None:
    statement = _statement_v1()
    statement["subject"] = ["not-a-dict", {"name": ""}]
    parsed = parse_provenance(_write(tmp_path, statement))
    assert parsed.subject_name is None


def test_parse_rejects_bundle_with_non_string_payload(tmp_path: Path) -> None:
    bundle = {"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": 123}}
    with pytest.raises(ParseError):
        parse_provenance(_write(tmp_path, bundle))


def test_source_repository_absent_when_no_workflow(tmp_path: Path) -> None:
    statement = _statement_v1(
        buildDefinition={"buildType": "bt", "externalParameters": {"foo": "bar"}}
    )
    parsed = parse_provenance(_write(tmp_path, statement))
    assert parsed.source_repository is None
    assert parsed.build_type == "bt"


def test_parse_jsonl_skips_blank_and_bad_lines(tmp_path: Path) -> None:
    target = tmp_path / "att.jsonl"
    target.write_text(
        "\n   \nnot-json-line\n" + json.dumps(_bundle(_statement_v1())) + "\n",
        encoding="utf-8",
    )
    parsed = parse_provenance(target)
    assert parsed.builder_id == _BUILDER


def test_local_collector_ignores_non_provenance_json(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, {"foo": "bar", "nested": {"a": 1}}, name="random.json")
    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts])
    report = collector.collect()
    assert not report.evidence
    assert not report.errors


def test_normalize_provenance_full(tmp_path: Path) -> None:
    parsed = parse_provenance(_write(tmp_path, _statement_v1()))
    ev = normalize_provenance(parsed, _release())
    assert ev.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    assert ev.status == EvidenceStatus.GENERATED
    assert ev.subject_ref == "pkg:pypi/demo@1.0.0"
    assert ev.producer == _BUILDER
    assert ev.metadata["build_type"] == "https://actions.github.io/buildtypes/workflow/v1"
    assert ev.metadata["envelope"] == "statement"
    assert ev.metadata["invocation_id"] == "https://github.com/acme/app/actions/runs/123"
    assert ev.metadata["source_repository"] == "https://github.com/acme/app"
    assert ev.evidence_id.startswith("prov-")


def test_normalize_provenance_subject_falls_back_to_builder(tmp_path: Path) -> None:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": _PROV_V1,
        "predicate": {
            "buildDefinition": {"buildType": "bt"},
            "runDetails": {"builder": {"id": "bldr"}},
        },
    }
    parsed = parse_provenance(_write(tmp_path, statement))
    ev = normalize_provenance(parsed, _release())
    assert ev.subject_ref == "bldr"
    assert "invocation_id" not in ev.metadata
    assert "source_repository" not in ev.metadata


def test_local_collector_ingests_provenance(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _bundle(_statement_v1()), name="build.sigstore.json")
    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts])
    report = collector.collect()
    prov = [e for e in report.evidence if e.evidence_type == EvidenceType.ARTIFACT_ATTESTATION]
    assert len(prov) == 1
    assert prov[0].status == EvidenceStatus.GENERATED
    assert not report.errors
