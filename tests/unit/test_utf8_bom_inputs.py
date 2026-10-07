"""UTF-8 signatures are accepted without changing raw artifact hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.parsers import parse_osv
from evidence_collector.parsers._common import ParseError, load_json


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
