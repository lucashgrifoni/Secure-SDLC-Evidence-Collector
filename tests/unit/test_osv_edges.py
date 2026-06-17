"""Edge and error-path tests for the OSV / OSV-Scanner parser.

Happy paths and the unknown-shape rejection live in ``test_parsers.py``.
These tests pin the severity bucketing thresholds, the CVSS score
extraction fallbacks, and the defensive skips for malformed entries in
both the scanner-envelope and single-record shapes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_collector.parsers import parse_osv


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    target = tmp_path / "osv.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_osv_severity_buckets_info_and_medium(tmp_path: Path) -> None:
    # 0.0 -> info (the lowest bucket), 5.5 -> medium (the 4.0..7.0 band).
    path = _write(
        tmp_path,
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "a", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {"id": "OSV-1", "severity": [{"type": "CVSS_V3", "score": "0.0"}]},
                                {"id": "OSV-2", "severity": [{"type": "CVSS_V3", "score": "5.5"}]},
                            ],
                        }
                    ]
                }
            ]
        },
    )
    parsed = parse_osv(path)
    assert parsed.total_findings == 2
    assert parsed.findings_count["info"] == 1
    assert parsed.findings_count["medium"] == 1


def test_parse_osv_cvss_score_extraction_variants(tmp_path: Path) -> None:
    # The bucket reflects the highest score that can be parsed across a
    # noisy severity list: a non-dict entry, a non-string score, a junk
    # string, a plain numeric string, and a vector with a trailing score.
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"
    path = _write(
        tmp_path,
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "b", "ecosystem": "PyPI"},
                            "vulnerabilities": [
                                {
                                    "id": "OSV-3",
                                    "severity": [
                                        "not-a-dict",
                                        {"type": "CVSS_V3", "score": 7.5},
                                        {"type": "CVSS_V3", "score": "abc"},
                                        {"type": "CVSS_V3", "score": "7.0"},
                                        {"type": "CVSS_V3", "score": vector},
                                    ],
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    )
    parsed = parse_osv(path)
    assert parsed.total_findings == 1
    assert parsed.findings_count["critical"] == 1


def test_parse_osv_bucket_defaults_to_medium_when_unparseable(tmp_path: Path) -> None:
    # Severity present but nothing parseable -> medium fallback.
    path = _write(
        tmp_path,
        {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "c", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {"id": "OSV-4", "severity": [{"score": None}, {"score": 5}]}
                            ],
                        }
                    ]
                }
            ]
        },
    )
    parsed = parse_osv(path)
    assert parsed.findings_count["medium"] == 1


def test_parse_osv_envelope_skips_malformed_entries(tmp_path: Path) -> None:
    # Only the single well-formed vulnerability is counted; every malformed
    # result/package/vuln shape is skipped without raising.
    path = _write(
        tmp_path,
        {
            "results": [
                "not-a-dict",
                {"packages": "not-a-list"},
                {
                    "packages": [
                        "not-a-dict-entry",
                        {"vulnerabilities": "not-a-list"},
                        {"package": {"name": "x"}, "vulnerabilities": []},
                        {
                            "package": {"name": "y", "ecosystem": "npm"},
                            "vulnerabilities": [
                                "not-a-dict",
                                {"id": "GHSA-1", "aliases": ["CVE-2030-1111", 123]},
                            ],
                        },
                    ]
                },
            ]
        },
    )
    parsed = parse_osv(path)
    assert parsed.tool_name == "osv-scanner"
    assert parsed.total_findings == 1
    assert parsed.findings_count["medium"] == 1
    assert parsed.package_count == 1
    assert parsed.ecosystems == ["npm"]
    assert parsed.cve_ids == ["CVE-2030-1111"]


def test_parse_osv_single_record_skips_malformed_affected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "id": "GHSA-zzzz",
            "aliases": ["CVE-2031-2222", False],
            "affected": [
                "not-a-dict",
                {"ranges": []},
                {"package": {"name": "foo", "ecosystem": "crates.io"}},
            ],
            "severity": [{"type": "CVSS_V3", "score": "2.0"}],
        },
    )
    parsed = parse_osv(path)
    assert parsed.tool_name == "osv"
    assert parsed.total_findings == 1
    assert parsed.findings_count["low"] == 1
    assert parsed.ecosystems == ["crates.io"]
    assert parsed.cve_ids == ["CVE-2031-2222"]
    assert parsed.package_count == 1
