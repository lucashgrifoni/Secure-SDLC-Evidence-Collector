"""UTF-8 signatures are accepted without changing raw artifact hashes."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.intelligence.epss import load_epss_feed
from evidence_collector.intelligence.kev import load_kev_feed
from evidence_collector.parsers import parse_osv
from evidence_collector.parsers._common import ParseError, load_json
from evidence_collector.parsers.garak import parse_garak
from evidence_collector.parsers.intoto_statement import parse_intoto_statements


def test_utf8_bom_is_read_as_json(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"value": "ação"}', encoding="utf-8-sig")
    assert load_json(path) == {"value": "ação"}


def test_bom_artifact_is_detected_collected_and_hashed_as_supplied(tmp_path: Path) -> None:
    path = tmp_path / "osv.json"
    path.write_text(
        json.dumps(
            {
                "id": "GHSA-test-0001",
                "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}}],
            }
        ),
        encoding="utf-8-sig",
    )
    parsed = parse_osv(path)
    assert (
        parsed.artifact.integrity_hash == "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    )
    report = LocalArtifactCollector(
        ReleaseContext(release_id="1", commit_sha="abcdef1234567890"),
        artifacts_dirs=[tmp_path],
    ).collect()
    assert len(report.evidence) == 1
    assert report.errors == []
    assert report.ignored == []


def test_utf16_is_still_rejected_as_an_encoding_error(tmp_path: Path) -> None:
    path = tmp_path / "input.json"
    path.write_text('{"value": 1}', encoding="utf-16")
    with pytest.raises(ParseError, match="text encoding"):
        load_json(path)


def _statement(predicate_type: str, predicate: dict[str, Any]) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "app.tar.gz", "digest": {"sha256": "cafe"}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def _dsse(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [{"sig": "AAAA"}],
    }


_PROVENANCE = _statement(
    "https://slsa.dev/provenance/v1",
    {
        "buildDefinition": {"buildType": "https://example.com/build"},
        "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
    },
)
_RELEASE = _statement(
    "https://in-toto.io/attestation/release/v0.2",
    {"purl": "pkg:pypi/demo@1.0.0", "packageId": "demo"},
)
_TEST_RESULT = _statement(
    "https://in-toto.io/attestation/test-result/v0.1",
    {"result": "PASSED", "configuration": [{"name": "ci.yml"}], "passedTests": ["a"]},
)


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        (_PROVENANCE, "slsa-provenance"),
        (_dsse(_PROVENANCE), "slsa-provenance"),
        (
            {
                "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                "dsseEnvelope": _dsse(_PROVENANCE),
                "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}},
            },
            "slsa-provenance",
        ),
        (_RELEASE, "release-attestation"),
        (_TEST_RESULT, "in-toto-test-result"),
        (_dsse(_TEST_RESULT), "in-toto-test-result"),
    ],
    ids=["slsa", "dsse", "sigstore-bundle", "release", "statement", "dsse-statement"],
)
def test_bom_attestations_are_collected_not_ignored(
    tmp_path: Path, payload: dict[str, Any], kind: str
) -> None:
    (tmp_path / "statement.intoto.json").write_text(json.dumps(payload), encoding="utf-8-sig")
    report = LocalArtifactCollector(
        ReleaseContext(release_id="1", commit_sha="abcdef1234567890"),
        artifacts_dirs=[tmp_path],
    ).collect()
    assert report.ignored == []
    assert report.errors == []
    assert [e.source.kind for e in report.evidence] == [kind]


def test_bom_jsonl_statement_parses_directly(tmp_path: Path) -> None:
    path = tmp_path / "statements.jsonl"
    path.write_text(json.dumps(_TEST_RESULT) + "\n", encoding="utf-8-sig")
    assert len(parse_intoto_statements(path)) == 1


def test_bom_kev_epss_and_garak_feeds_are_read(tmp_path: Path) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text(
        json.dumps({"dateReleased": "2026-05-17", "vulnerabilities": [{"cveID": "CVE-2023-1"}]}),
        encoding="utf-8-sig",
    )
    assert load_kev_feed(kev).get("CVE-2023-1") is not None
    epss = tmp_path / "epss.csv"
    epss.write_text(
        "#model_version:v2026.05.01,score_date:2026-05-17T00:00:00+0000\n"
        "cve,epss,percentile\nCVE-2023-1,0.5,0.9\n",
        encoding="utf-8-sig",
    )
    feed = load_epss_feed(epss)
    assert feed.model_version == "v2026.05.01"
    assert feed.get("CVE-2023-1") is not None
    garak = tmp_path / "run.garak.jsonl"
    garak.write_text(
        '{"entry_type":"init","garak_version":"0.10.0","model_name":"m"}\n'
        '{"entry_type":"digest","probe":"p.Probe","attempts":2,"hits":1}\n',
        encoding="utf-8-sig",
    )
    assert parse_garak(garak).tool_version == "0.10.0"
