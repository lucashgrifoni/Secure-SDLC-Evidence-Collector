"""Unit tests for the OWASP ZAP JSON parser and normalizer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.normalizers import normalize_zap
from evidence_collector.parsers import parse_zap
from evidence_collector.parsers._common import ParseError


def _write_zap(path: Path, alerts: list[dict[str, object]]) -> Path:
    document = {
        "@version": "2.14.0",
        "@generator": "OWASP ZAP",
        "site": [
            {
                "@name": "https://app.example.com",
                "alerts": alerts,
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_parse_zap_counts_severities(tmp_path: Path) -> None:
    path = _write_zap(
        tmp_path / "zap.json",
        alerts=[
            {"name": "SQL injection", "riskcode": "3", "count": "1"},
            {"name": "Info leak", "riskcode": "0", "count": "2"},
            {"name": "Missing header", "riskcode": "1", "count": "4"},
        ],
    )
    parsed = parse_zap(path)
    assert parsed.tool_name == "OWASP ZAP"
    assert parsed.total_findings == 7
    assert parsed.findings_count["high"] == 1
    assert parsed.findings_count["low"] == 4
    assert parsed.findings_count["info"] == 2
    assert parsed.target_urls == ["https://app.example.com"]


def test_normalize_zap_passed_and_failed(tmp_path: Path, sample_release) -> None:
    clean = _write_zap(
        tmp_path / "clean.json",
        alerts=[
            {"name": "Info", "riskcode": "0"},
        ],
    )
    dirty = _write_zap(
        tmp_path / "dirty.json",
        alerts=[
            {"name": "XSS", "riskcode": "3"},
        ],
    )

    clean_parsed = parse_zap(clean)
    dirty_parsed = parse_zap(dirty)

    clean_ev = normalize_zap(clean_parsed, sample_release)
    dirty_ev = normalize_zap(dirty_parsed, sample_release)

    assert clean_ev.evidence_type == EvidenceType.DAST_SCAN
    assert clean_ev.status == EvidenceStatus.PASSED
    assert dirty_ev.status == EvidenceStatus.FAILED


def test_parse_zap_rejects_document_without_site(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"version": "2.14.0"}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_zap(path)
