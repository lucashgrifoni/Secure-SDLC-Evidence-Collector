"""Tests for the GitLab Security Report parser.

Every report under ``tests/fixtures/real/gitlab/`` was written by a GitLab
analyzer image; the README beside them records the image, tag and command.
The few tests that need a state no capture produced (a failed scan, a
low-severity secret, an unfamiliar severity word) start from a real report
and change exactly one field, and say so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_gitlab_security_report
from evidence_collector.parsers import parse_gitlab_security_report
from evidence_collector.parsers._common import ParseError
from evidence_collector.parsers.gitlab_security import looks_like_gitlab_security_report

REAL = Path(__file__).resolve().parents[1] / "fixtures" / "real" / "gitlab"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890", branch="main")


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((REAL / name).read_text(encoding="utf-8"))
    return data


def _write(directory: Path, payload: Any, name: str) -> Path:
    target = directory / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _evidence(path: Path) -> Any:
    return normalize_gitlab_security_report(parse_gitlab_security_report(path), _release())


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "gl-sast-report.json",
        "gl-secret-detection-report.json",
        "gl-container-scanning-report.json",
        "gl-dependency-scanning-report.json",
        "gl-dast-report.json",
    ],
)
def test_every_real_capture_is_recognized(name: str) -> None:
    assert looks_like_gitlab_security_report(_load(name))


def test_an_unsupported_scan_type_is_not_claimed() -> None:
    # API fuzzing and coverage fuzzing reports share the schema, but no
    # capture of them exists here, so they stay unread as before.
    report = _load("gl-sast-report.json")
    report["scan"]["type"] = "api_fuzzing"
    assert not looks_like_gitlab_security_report(report)


@pytest.mark.parametrize("scan_type", [["sast"], {"type": "sast"}])
def test_a_scan_type_that_is_not_a_string_is_not_claimed(scan_type: Any) -> None:
    # A list or an object is unhashable; the membership test must not raise.
    report = _load("gl-sast-report.json")
    report["scan"]["type"] = scan_type
    assert not looks_like_gitlab_security_report(report)


def test_a_schema_major_other_than_15_is_not_claimed() -> None:
    report = _load("gl-sast-report.json")
    report["version"] = "14.1.2"
    assert not looks_like_gitlab_security_report(report)


@pytest.mark.parametrize(
    "data",
    [
        [],
        {"version": "15.2.4", "vulnerabilities": []},
        {"version": "15.2.4", "scan": {"type": "sast"}},
        {"SchemaVersion": 2, "Results": []},
    ],
)
def test_other_json_is_not_claimed(data: Any) -> None:
    assert not looks_like_gitlab_security_report(data)


def test_parsing_a_file_that_is_not_a_report_fails(tmp_path: Path) -> None:
    path = _write(tmp_path, {"runs": []}, "other.json")
    with pytest.raises(ParseError, match="not a GitLab Security Report"):
        parse_gitlab_security_report(path)


# ---------------------------------------------------------------------------
# Real captures
# ---------------------------------------------------------------------------


def test_sast_report_is_a_failed_sast_scan() -> None:
    evidence = _evidence(REAL / "gl-sast-report.json")
    assert evidence.evidence_type is EvidenceType.SAST_SCAN
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.findings_count == {"high": 2, "medium": 1}
    assert evidence.producer == "semgrep"
    assert evidence.source.version == "1.185.0"
    assert evidence.subject_type is SubjectType.COMMIT
    assert evidence.subject_ref == "abcdef1234567890"
    assert evidence.metadata["gitlab_scan_type"] == "sast"
    assert evidence.metadata["gitlab_report_version"] == "15.2.4"
    assert evidence.metadata["gitlab_analyzer"] == {"id": "semgrep", "version": "6.33.0"}


def test_sast_cve_field_is_not_read_as_a_cve_id() -> None:
    # In a SAST report `cve` holds a location key such as
    # `semgrep_id:bandit.B307:14:14`; only identifiers typed `cve` count.
    assert _evidence(REAL / "gl-sast-report.json").cve_ids == []


def test_clean_sast_report_is_a_passed_scan_with_zero_findings() -> None:
    evidence = _evidence(REAL / "gl-sast-report-clean.json")
    assert evidence.evidence_type is EvidenceType.SAST_SCAN
    assert evidence.status is EvidenceStatus.PASSED
    assert evidence.findings_count == {}


def test_secret_detection_report_fails_the_secrets_scan() -> None:
    evidence = _evidence(REAL / "gl-secret-detection-report.json")
    assert evidence.evidence_type is EvidenceType.SECRETS_SCAN
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.findings_count == {"critical": 1}
    assert evidence.producer == "gitleaks"


def test_any_secret_fails_the_scan_whatever_its_severity(tmp_path: Path) -> None:
    # Derived from the real capture: only the severity word is lowered.
    report = _load("gl-secret-detection-report.json")
    report["vulnerabilities"][0]["severity"] = "Low"
    evidence = _evidence(_write(tmp_path, report, "gl-secret-detection-report.json"))
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.findings_count == {"low": 1}
    assert "any finding fails a secrets scan" in evidence.summary


def test_clean_secret_detection_report_passes() -> None:
    evidence = _evidence(REAL / "gl-secret-detection-report-clean.json")
    assert evidence.evidence_type is EvidenceType.SECRETS_SCAN
    assert evidence.status is EvidenceStatus.PASSED


def test_container_scanning_report_is_a_dependency_scan_with_cve_ids() -> None:
    evidence = _evidence(REAL / "gl-container-scanning-report.json")
    assert evidence.evidence_type is EvidenceType.SCA_SCAN
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.findings_count == {"critical": 4, "high": 34, "medium": 10}
    assert "CVE-2021-36159" in evidence.cve_ids
    assert evidence.producer == "trivy"
    assert evidence.subject_type is SubjectType.ARTIFACT
    assert evidence.metadata["gitlab_scan_type"] == "container_scanning"
    assert evidence.metadata["image"] == "docker.io/library/alpine:3.14.0"


def test_clean_container_scanning_report_passes() -> None:
    evidence = _evidence(REAL / "gl-container-scanning-report-clean.json")
    assert evidence.evidence_type is EvidenceType.SCA_SCAN
    assert evidence.status is EvidenceStatus.PASSED
    assert "image" not in evidence.metadata


def test_dependency_scanning_report_is_a_dependency_scan() -> None:
    evidence = _evidence(REAL / "gl-dependency-scanning-report.json")
    assert evidence.evidence_type is EvidenceType.SCA_SCAN
    assert evidence.status is EvidenceStatus.FAILED
    assert evidence.findings_count == {"critical": 2, "high": 6, "medium": 13}
    assert "CVE-2020-1747" in evidence.cve_ids
    assert evidence.producer == "gemnasium-python"


def test_dast_report_without_high_findings_passes() -> None:
    evidence = _evidence(REAL / "gl-dast-report.json")
    assert evidence.evidence_type is EvidenceType.DAST_SCAN
    assert evidence.status is EvidenceStatus.PASSED
    assert evidence.findings_count == {"low": 2, "info": 1}
    assert evidence.producer == "browserker"


# ---------------------------------------------------------------------------
# Scan status and severity words
# ---------------------------------------------------------------------------


def test_a_failed_scan_is_invalid_evidence(tmp_path: Path) -> None:
    # Derived from the real clean capture: only `scan.status` is changed.
    report = _load("gl-sast-report-clean.json")
    report["scan"]["status"] = "failure"
    evidence = _evidence(_write(tmp_path, report, "gl-sast-report.json"))
    assert evidence.status is EvidenceStatus.INVALID
    assert evidence.confidence is ConfidenceLevel.LOW
    assert evidence.metadata["gitlab_scan_status"] == "failure"
    assert "did not complete" in evidence.summary


def test_a_failed_scan_with_findings_is_still_invalid(tmp_path: Path) -> None:
    report = _load("gl-sast-report.json")
    report["scan"]["status"] = "failure"
    evidence = _evidence(_write(tmp_path, report, "gl-sast-report.json"))
    assert evidence.status is EvidenceStatus.INVALID


def test_an_unfamiliar_severity_word_counts_as_unknown(tmp_path: Path) -> None:
    report = _load("gl-dast-report.json")
    report["vulnerabilities"][0]["severity"] = "Severe"
    evidence = _evidence(_write(tmp_path, report, "gl-dast-report.json"))
    assert evidence.findings_count == {"unknown": 1, "low": 1, "info": 1}


def test_evidence_ids_are_deterministic_and_differ_per_report() -> None:
    first = _evidence(REAL / "gl-sast-report.json").evidence_id
    again = _evidence(REAL / "gl-sast-report.json").evidence_id
    other = _evidence(REAL / "gl-dast-report.json").evidence_id
    assert first == again
    assert first != other
    assert first.startswith("gitlab-")


# ---------------------------------------------------------------------------
# Collector dispatch
# ---------------------------------------------------------------------------


def test_collector_ingests_every_real_capture(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for name in (
        "gl-sast-report.json",
        "gl-secret-detection-report.json",
        "gl-container-scanning-report.json",
        "gl-dependency-scanning-report.json",
        "gl-dast-report.json",
    ):
        (artifacts / name).write_bytes((REAL / name).read_bytes())
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert report.errors == []
    assert report.ignored == []
    assert sorted(e.evidence_type.value for e in report.evidence) == [
        "dast_scan",
        "sast_scan",
        "sca_scan",
        "sca_scan",
        "secrets_scan",
    ]


def test_collector_still_ignores_an_unsupported_scan_type(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    report = _load("gl-sast-report.json")
    report["scan"]["type"] = "coverage_fuzzing"
    _write(artifacts, report, "gl-coverage-fuzzing-report.json")
    collected = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert collected.evidence == []
    assert len(collected.ignored) == 1


def test_collector_ignores_a_malformed_scan_type_and_keeps_the_valid_report(
    tmp_path: Path,
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "gl-sast-report.json").write_bytes((REAL / "gl-sast-report.json").read_bytes())
    report = _load("gl-sast-report.json")
    report["scan"]["type"] = ["sast"]
    _write(artifacts, report, "gl-malformed-report.json")
    collected = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert collected.errors == []
    assert [e.evidence_type.value for e in collected.evidence] == ["sast_scan"]
    assert [Path(p).name for p in collected.ignored] == ["gl-malformed-report.json"]
