"""Edge and error-path tests for the SARIF parser.

The happy path lives in ``test_parsers.py``; these tests pin the
defensive branches: missing severity, malformed runs/results, and the
CVE-mining helpers that scrape identifiers out of ``ruleId``,
``properties``, and ``message.text``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.parsers import parse_sarif
from evidence_collector.parsers._common import ParseError


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    target = tmp_path / "report.sarif"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_sarif_defaults_missing_level_to_medium(tmp_path: Path) -> None:
    # A result with no ``level`` must bucket as medium rather than crash.
    path = _write(
        tmp_path,
        {"runs": [{"tool": {"driver": {"name": "trivy"}}, "results": [{"ruleId": "X"}]}]},
    )
    parsed = parse_sarif(path)
    assert parsed.total_findings == 1
    assert parsed.findings_count["medium"] == 1


def test_parse_sarif_rejects_non_dict_first_run(tmp_path: Path) -> None:
    path = _write(tmp_path, {"runs": [42]})
    with pytest.raises(ParseError, match="malformed first run"):
        parse_sarif(path)


def test_parse_sarif_skips_malformed_runs_and_results(tmp_path: Path) -> None:
    # First run is valid; later entries and stray result types are skipped
    # rather than counted, so the total reflects only well-formed findings.
    path = _write(
        tmp_path,
        {
            "runs": [
                {"tool": {"driver": {"name": "semgrep"}}, "results": [{"level": "error"}, "nope"]},
                "not-a-run",
                {"results": "not-a-list"},
            ]
        },
    )
    parsed = parse_sarif(path)
    assert parsed.tool_name == "semgrep"
    assert parsed.total_findings == 1
    assert parsed.findings_count["high"] == 1


def test_parse_sarif_defaults_tool_metadata_when_absent(tmp_path: Path) -> None:
    # No driver name -> placeholder; semanticVersion is used when version
    # is absent.
    path = _write(
        tmp_path,
        {"runs": [{"tool": {"driver": {"semanticVersion": "1.2.3"}}, "results": []}]},
    )
    parsed = parse_sarif(path)
    assert parsed.tool_name == "unknown-sarif-tool"
    assert parsed.tool_version == "1.2.3"
    assert parsed.total_findings == 0


def test_parse_sarif_mines_cves_from_every_site(tmp_path: Path) -> None:
    # CVEs hide in ruleId, properties.tags, properties.cve/cveId/cveID, and
    # message.text; all sites are scraped and de-duplicated/upper-cased.
    path = _write(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner"}},
                    "results": [
                        {
                            "ruleId": "CVE-2023-1111",
                            "properties": {
                                "tags": ["CVE-2023-2222", 99],
                                "cve": "cve-2023-3333",
                                "cveId": ["CVE-2023-4444"],
                                "cveID": "CVE-2023-5555",
                            },
                            "message": {"text": "see CVE-2023-6666 for details"},
                        }
                    ],
                }
            ]
        },
    )
    parsed = parse_sarif(path)
    assert parsed.cve_ids == [
        "CVE-2023-1111",
        "CVE-2023-2222",
        "CVE-2023-3333",
        "CVE-2023-4444",
        "CVE-2023-5555",
        "CVE-2023-6666",
    ]
