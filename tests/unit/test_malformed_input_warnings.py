"""Malformed scanner and test input is recorded as before, with a warning.

The 4.3.0 end-user validation found three inputs read without a word: a
GitLab report whose vulnerability entries are not objects or whose
scan.status is neither success nor failure, a JUnit count that is not a
whole number, and a SARIF result level outside the SARIF enum. Each was
recorded as a high-confidence reading. The verdict rules stay as they were
(4.x does not start refusing input it accepted); the record now carries the
problem in metadata, at low confidence, and the run logs a warning.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from evidence_collector.domain.enums import ConfidenceLevel, EvidenceStatus
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers.engine import (
    normalize_gitlab_security_report,
    normalize_junit,
    normalize_sarif,
)
from evidence_collector.parsers.gitlab_security import parse_gitlab_security_report
from evidence_collector.parsers.junit import parse_junit
from evidence_collector.parsers.sarif import parse_sarifs


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.05.19", commit_sha="abcdef1234567890")


def _gitlab(tmp_path: Path, vulnerabilities: list[object], status: str | None) -> Path:
    scan: dict[str, object] = {
        "type": "sast",
        "analyzer": {"id": "semgrep", "version": "1"},
        "scanner": {"id": "semgrep", "version": "1"},
    }
    if status is not None:
        scan["status"] = status
    path = tmp_path / "gl-sast-report.json"
    path.write_text(
        json.dumps({"version": "15.2.1", "vulnerabilities": vulnerabilities, "scan": scan}),
        encoding="utf-8",
    )
    return path


def test_a_clean_gitlab_report_stays_high_confidence(tmp_path: Path) -> None:
    parsed = parse_gitlab_security_report(_gitlab(tmp_path, [], "success"))
    evidence = normalize_gitlab_security_report(parsed, _release())
    assert evidence.confidence == ConfidenceLevel.HIGH
    assert "gitlab_skipped_entries" not in evidence.metadata


def test_gitlab_entries_that_are_not_objects_are_counted_and_warned(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = _gitlab(tmp_path, ["CVE-2026-1", 7, {"severity": "Low"}], "success")
    with caplog.at_level(logging.WARNING):
        evidence = normalize_gitlab_security_report(parse_gitlab_security_report(path), _release())
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata["gitlab_skipped_entries"] == 2
    assert evidence.confidence == ConfidenceLevel.LOW
    assert "2 vulnerability entries that are not objects" in caplog.text


@pytest.mark.parametrize("status", [None, "succeeded", "partial"])
def test_gitlab_scan_status_other_than_success_or_failure_is_warned(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, status: str | None
) -> None:
    with caplog.at_level(logging.WARNING):
        evidence = normalize_gitlab_security_report(
            parse_gitlab_security_report(_gitlab(tmp_path, [], status)), _release()
        )
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.LOW
    assert "scan.status" in caplog.text


def test_junit_counts_that_are_not_whole_numbers_are_warned(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "junit.xml"
    path.write_text(
        '<testsuite tests="2" failures="one" errors="0.5">'
        '<testcase name="a"/><testcase name="b"><failure/></testcase></testsuite>',
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        evidence = normalize_junit(parse_junit(path), _release())
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.findings_count["failures"] == 1
    assert evidence.metadata["unreadable_count_attributes"] == ["failures='one'", "errors='0.5'"]
    assert evidence.confidence == ConfidenceLevel.LOW
    assert "not whole numbers" in caplog.text


def test_a_sarif_level_outside_the_enum_is_warned(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "scan.sarif"
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "semgrep", "rules": [{"id": "r"}]}},
                        "results": [
                            {"ruleId": "r", "level": "critical", "message": {"text": "x"}},
                            {"ruleId": "r", "level": "note", "message": {"text": "y"}},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        (parsed,) = parse_sarifs(path)
        evidence = normalize_sarif(parsed, _release())
    assert parsed.findings_count["medium"] == 1
    assert evidence.metadata["invalid_level_count"] == 1
    assert evidence.confidence == ConfidenceLevel.LOW
    assert "level that SARIF does not define" in caplog.text
