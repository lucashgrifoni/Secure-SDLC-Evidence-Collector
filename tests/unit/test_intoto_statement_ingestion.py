"""Tests for generic in-toto Statement ingestion.

The behaviour under test is the one that did not exist before: a Statement
whose predicateType has no dedicated parser used to be dropped silently.
These tests pin both halves of the fix — the recognized predicates (SVR,
test-result, vulns) mapping to real evidence types, and the unknown ones
surviving as generic attestations with a warning.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_intoto_statement
from evidence_collector.parsers import parse_intoto_statement, parse_intoto_statements
from evidence_collector.parsers._common import ParseError

_SVR = "https://in-toto.io/attestation/svr/v0.2"
_TEST_RESULT = "https://in-toto.io/attestation/test-result/v0.1"
_VULNS = "https://in-toto.io/attestation/vulns/v0.2"
_VSA = "https://slsa.dev/verification_summary/v1"
_UNKNOWN = "https://example.com/attestation/totally-made-up/v9"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="3.0.0", commit_sha="abcdef1234567890", branch="main")


def _statement(predicate_type: str, predicate: Any) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "app.tar.gz", "digest": {"sha256": "cafe"}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def _write(directory: Path, payload: Any, name: str = "stmt.json") -> Path:
    target = directory / name
    text = payload if isinstance(payload, str) else json.dumps(payload)
    target.write_text(text, encoding="utf-8")
    return target


def _dsse(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [{"sig": "AAAA"}],
    }


def _provenance() -> dict[str, Any]:
    return _statement(
        "https://slsa.dev/provenance/v1",
        {
            "buildDefinition": {"buildType": "https://example.com/build"},
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
        },
    )


def _svr_payload() -> dict[str, Any]:
    return _statement(
        _SVR,
        {
            "verifier": {"id": "https://example.com/policy_engine/v1", "policies": []},
            "timeCreated": "2026-08-07T12:00:00Z",
            "properties": ["SLSA_BUILD_LEVEL_3", "EXAMPLE_DEPLOYMENT_APPROVED"],
        },
    )


def _test_result_payload(result: str = "PASSED") -> dict[str, Any]:
    return _statement(
        _TEST_RESULT,
        {
            "result": result,
            "configuration": [{"name": ".github/workflows/ci.yml"}],
            "url": "https://example.com/runs/1",
            "passedTests": ["a", "b"],
            "warnedTests": ["c"],
            "failedTests": [],
        },
    )


def _vulns_payload(severity: str = "medium") -> dict[str, Any]:
    return _statement(
        _VULNS,
        {
            "scanner": {
                "uri": "pkg:github/aquasecurity/trivy",
                "version": "0.19.2",
                "db": {"lastUpdate": "2026-08-01T00:00:00Z"},
                "result": [
                    {"id": "CVE-2026-1", "severity": [{"method": "nvd", "score": severity}]},
                    {
                        "id": "CVE-2026-2",
                        "severity": [{"method": "cvss_score", "score": "5.2"}],
                    },
                ],
            },
            "metadata": {
                "scanStartedOn": "2026-08-01T00:00:00Z",
                "scanFinishedOn": "2026-08-01T00:10:00Z",
            },
        },
    )


# ---------------------------------------------------------------------------
# Recognized predicates
# ---------------------------------------------------------------------------


def test_svr_becomes_artifact_attestation(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _svr_payload()))
    assert parsed.recognized is True
    assert parsed.verifier_id == "https://example.com/policy_engine/v1"
    assert parsed.properties == ["SLSA_BUILD_LEVEL_3", "EXAMPLE_DEPLOYMENT_APPROVED"]
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    assert ev.status == EvidenceStatus.GENERATED
    assert ev.source.kind == "in-toto-svr"
    assert ev.metadata["properties"] == ["SLSA_BUILD_LEVEL_3", "EXAMPLE_DEPLOYMENT_APPROVED"]
    assert ev.metadata["time_created"] == "2026-08-07T12:00:00Z"


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ("PASSED", EvidenceStatus.PASSED),
        ("FAILED", EvidenceStatus.FAILED),
        # Ran to completion but flagged warnings: neither a clean pass nor a
        # failure the attestation actually asserted.
        ("WARNED", EvidenceStatus.COMPLETED),
        ("something-else", EvidenceStatus.UNKNOWN),
    ],
)
def test_test_result_status_mapping(tmp_path: Path, result: str, expected: EvidenceStatus) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _test_result_payload(result)))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.evidence_type == EvidenceType.TEST_RESULT
    assert ev.status == expected


def test_test_result_counts_are_recorded(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _test_result_payload()))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.metadata["passed_tests"] == 2
    assert ev.metadata["warned_tests"] == 1
    assert ev.metadata["failed_tests"] == 0
    assert ev.metadata["test_url"] == "https://example.com/runs/1"


def test_vulns_becomes_sca_scan_with_cve_ids(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _vulns_payload()))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.evidence_type == EvidenceType.SCA_SCAN
    assert ev.cve_ids == ["CVE-2026-1", "CVE-2026-2"]
    assert ev.metadata["scanner_uri"] == "pkg:github/aquasecurity/trivy"
    assert ev.metadata["scanner_version"] == "0.19.2"


def test_vulns_numeric_score_is_not_guessed_into_a_bucket(tmp_path: Path) -> None:
    # CVE-2026-2 carries only a numeric CVSS score. Cut points differ per
    # scoring system, so it must land in `unknown`, never in `medium`.
    parsed = parse_intoto_statement(_write(tmp_path, _vulns_payload()))
    assert parsed.findings_count == {"medium": 1, "unknown": 1}


def test_vulns_high_severity_fails_the_evidence(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _vulns_payload("critical")))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.status == EvidenceStatus.FAILED


def test_vulns_without_blocking_severity_passes(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _vulns_payload("low")))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.status == EvidenceStatus.PASSED


# ---------------------------------------------------------------------------
# Unknown predicates survive
# ---------------------------------------------------------------------------


def test_unknown_predicate_becomes_generic_attestation(tmp_path: Path) -> None:
    parsed = parse_intoto_statement(_write(tmp_path, _statement(_UNKNOWN, {"anything": 1})))
    assert parsed.recognized is False
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.evidence_type == EvidenceType.GENERIC_ATTESTATION
    # No verdict is invented on the attestation's behalf.
    assert ev.status == EvidenceStatus.UNKNOWN
    assert ev.metadata["predicate_type"] == _UNKNOWN
    assert ev.metadata["predicate_recognized"] is False


def test_unknown_predicate_without_a_predicate_body_is_still_kept(tmp_path: Path) -> None:
    payload = _statement(_UNKNOWN, "not-an-object")
    parsed = parse_intoto_statement(_write(tmp_path, payload))
    ev = normalize_intoto_statement(parsed, _release())
    assert ev.evidence_type == EvidenceType.GENERIC_ATTESTATION


def test_file_with_no_statement_at_all_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_intoto_statement(_write(tmp_path, {"hello": "world"}))


# ---------------------------------------------------------------------------
# Boundaries with the dedicated parsers
# ---------------------------------------------------------------------------


def test_generic_route_does_not_claim_provenance(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_intoto_statement(_write(tmp_path, _provenance()))


def test_collector_ingests_provenance_exactly_once(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _provenance(), name="prov.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [e.source.kind for e in report.evidence] == ["slsa-provenance"]


def test_collector_ingests_raw_vsa_through_the_dedicated_route(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    vsa = _statement(
        _VSA,
        {
            "verifier": {"id": "https://example.com/verifier"},
            "resourceUri": "pkg:pypi/demo@1.0.0",
            "policy": {"uri": "https://example.com/policy"},
            "verificationResult": "PASSED",
            "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
        },
    )
    _write(artifacts, vsa, name="vsa.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [e.source.kind for e in report.evidence] == ["slsa-vsa"]


def test_collector_recovers_a_dsse_wrapped_vsa_generically(tmp_path: Path) -> None:
    # The dedicated VSA parser reads raw Statements only, so a signed VSA
    # was previously claimed by nobody and vanished. It must now survive as
    # a generic attestation rather than being dropped.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    vsa = _statement(_VSA, {"verifier": {"id": "x"}, "verificationResult": "PASSED"})
    _write(artifacts, _dsse(vsa), name="vsa.dsse.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert len(report.evidence) == 1
    assert report.evidence[0].evidence_type == EvidenceType.GENERIC_ATTESTATION
    assert report.evidence[0].metadata["envelope"] == "dsse"


# ---------------------------------------------------------------------------
# End-to-end through the collector
# ---------------------------------------------------------------------------


def test_collector_ingests_unknown_predicate_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _statement(_UNKNOWN, {"x": 1}), name="mystery.json")
    with caplog.at_level(logging.WARNING):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert len(report.evidence) == 1
    assert report.evidence[0].evidence_type == EvidenceType.GENERIC_ATTESTATION
    assert _UNKNOWN in caplog.text
    assert not report.errors


def test_collector_ingests_recognized_predicate_without_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _svr_payload(), name="svr.json")
    with caplog.at_level(logging.WARNING):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert len(report.evidence) == 1
    assert "unrecognized" not in caplog.text


def test_collector_ingests_provenance_and_unknown_from_one_jsonl(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    lines = "\n".join(
        json.dumps(record) for record in (_provenance(), _statement(_UNKNOWN, {"x": 1}))
    )
    _write(artifacts, lines, name="mixed.jsonl")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    kinds = sorted(e.source.kind for e in report.evidence)
    assert kinds == ["in-toto-statement", "slsa-provenance"]


# ---------------------------------------------------------------------------
# Multi-record files: every Statement is ingested, not just the first
# ---------------------------------------------------------------------------
#
# A JSONL is the multi-attestation format. Returning only the first match made
# every attestation after it vanish with exit 0 and no warning — and because
# this module's matcher accepts every predicate no dedicated parser claims,
# an SVR, a failing test-result and an unknown predicate collapsed into one
# "family" where exactly one survived.


def _jsonl(directory: Path, statements: list[dict[str, Any]], name: str) -> Path:
    return _write(
        directory,
        "\n".join(json.dumps(_dsse(s)) for s in statements),
        name=name,
    )


def test_jsonl_with_three_predicates_yields_three_records(tmp_path: Path) -> None:
    path = _jsonl(
        tmp_path,
        [_svr_payload(), _test_result_payload("FAILED"), _statement(_UNKNOWN, {"x": 1})],
        "attestations.jsonl",
    )
    parsed = parse_intoto_statements(path)
    assert [p.predicate_type for p in parsed] == [_SVR, _TEST_RESULT, _UNKNOWN]


def test_jsonl_with_two_statements_of_the_same_predicate_yields_both(tmp_path: Path) -> None:
    path = _jsonl(tmp_path, [_vulns_payload("low"), _vulns_payload("critical")], "vulns.jsonl")
    parsed = parse_intoto_statements(path)
    assert len(parsed) == 2
    assert [p.findings_count.get("low", 0) for p in parsed] == [1, 0]
    assert [p.findings_count.get("critical", 0) for p in parsed] == [0, 1]


def test_collector_ingests_every_statement_in_a_jsonl(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _jsonl(
        artifacts,
        [_svr_payload(), _test_result_payload("FAILED"), _statement(_UNKNOWN, {"x": 1})],
        "attestations.jsonl",
    )
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert len(report.evidence) == 3
    assert sorted(e.evidence_type for e in report.evidence) == sorted(
        [
            EvidenceType.ARTIFACT_ATTESTATION,
            EvidenceType.TEST_RESULT,
            EvidenceType.GENERIC_ATTESTATION,
        ]
    )
    # The FAILED test-result must survive — losing it is losing a red signal.
    test_evidence = next(e for e in report.evidence if e.evidence_type == EvidenceType.TEST_RESULT)
    assert test_evidence.status == EvidenceStatus.FAILED
    assert not report.errors


def test_warning_fires_once_per_unrecognized_statement_not_only_the_survivor(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    other = "https://example.com/attestation/second-unknown/v1"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _jsonl(
        artifacts,
        [_statement(_UNKNOWN, {"a": 1}), _statement(other, {"b": 2})],
        "unknowns.jsonl",
    )
    with caplog.at_level(logging.WARNING):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert len(report.evidence) == 2
    assert _UNKNOWN in caplog.text
    assert other in caplog.text


def test_single_statement_file_still_yields_exactly_one(tmp_path: Path) -> None:
    parsed = parse_intoto_statements(_write(tmp_path, _svr_payload()))
    assert len(parsed) == 1


def test_two_statements_of_one_predicate_get_distinct_evidence_ids(tmp_path: Path) -> None:
    """Two vulns attestations in one JSONL used to share an evidence id.

    The id was built from the file hash, the predicate type and the release, and
    all three are the same for both lines. The bundle then refused itself over
    a duplicate id, so `run` ended without writing any report.
    """
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.domain.models import Application

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _jsonl(artifacts, [_vulns_payload("low"), _vulns_payload("critical")], "vulns.jsonl")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    ids = [e.evidence_id for e in report.evidence]
    assert len(ids) == 2
    assert len(set(ids)) == 2

    result = run_pipeline(
        Application(name="demo", repository="acme/demo"),
        _release(),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
    )
    assert result.json_path is not None and result.json_path.is_file()
    assert len(result.bundle.evidence) == 2


def test_a_single_statement_keeps_the_evidence_id_it_had_before(tmp_path: Path) -> None:
    """Only the second and later Statements of a file take a position in their id.

    A file with one Statement hashes to the id it always had, so bundles built
    from such files are unchanged by the discriminator.
    """
    import hashlib

    parsed = parse_intoto_statements(_jsonl(tmp_path, [_vulns_payload("low")], "one.jsonl"))[0]
    evidence = normalize_intoto_statement(parsed, _release())
    parts = [parsed.artifact.integrity_hash, parsed.predicate_type, _release().release_id]
    digest = hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()[:12]
    assert evidence.evidence_id == f"stmt-{digest}"
