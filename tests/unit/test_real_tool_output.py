"""Parsers and normalizers against captured real scanner output.

Every file under ``tests/fixtures/real/`` was written by the tool named in
the README beside it, with the version and command recorded there. Before
these captures existed every parser test used hand-made input, and the
hand-made SARIF put ``level`` on each result with no ``rules``, the reverse
of what Semgrep, Gitleaks and KICS actually write. These tests pin what the
collector concludes from the real shapes.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import ConfidenceLevel, EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_junit, normalize_sarif, normalize_trivy_json
from evidence_collector.parsers import parse_junit, parse_sarif, parse_trivy_json
from evidence_collector.parsers.trivy_json import looks_like_trivy_json

REAL = Path(__file__).resolve().parents[1] / "fixtures" / "real"


def test_semgrep_rule_defaults_and_inline_suppression(sample_release: ReleaseContext) -> None:
    # Semgrep 1.179.0 writes no result level; the severity is the rule's
    # defaultConfiguration. The third result sits on a `# nosemgrep` line and
    # Semgrep itself printed "2 findings".
    parsed = parse_sarif(REAL / "semgrep" / "semgrep.sarif")
    assert parsed.tool_name == "Semgrep OSS"
    assert parsed.total_findings == 2
    assert parsed.findings_count["high"] == 1
    assert parsed.findings_count["medium"] == 1
    assert parsed.suppressed_count == 1

    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SAST_SCAN
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata == {"suppressed_count": 1}
    assert evidence.summary is not None
    assert "1 suppressed result(s) not counted" in evidence.summary


def test_semgrep_rule_parse_error_is_a_warning_not_a_clean_scan(
    sample_release: ReleaseContext, caplog: pytest.LogCaptureFixture
) -> None:
    # Semgrep exited 2 on a broken rule but still wrote executionSuccessful
    # true, zero rules and zero results. The error notification is the only
    # sign; it lowers confidence and is logged, the status stays as reported.
    parsed = parse_sarif(REAL / "semgrep" / "rule-error.sarif")
    assert parsed.execution_failed is False
    assert parsed.tool_error_count == 1
    assert parsed.total_findings == 0

    with caplog.at_level(logging.WARNING, logger="evidence_collector"):
        evidence = normalize_sarif(parsed, sample_release)
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.LOW
    assert evidence.metadata == {"tool_error_notifications": 1}
    assert any("error notification" in record.getMessage() for record in caplog.records)


def test_gitleaks_leak_fails_the_secrets_scan_with_severity_as_reported(
    sample_release: ReleaseContext,
) -> None:
    # Gitleaks 8.30.1 sets no level and its rules carry no default, so the
    # SARIF level is the spec default `warning` (medium). The finding is a
    # detected secret, and any secret fails the scan whatever its level.
    parsed = parse_sarif(REAL / "gitleaks" / "leak.sarif")
    assert parsed.total_findings == 1
    assert parsed.findings_count["medium"] == 1
    assert parsed.findings_count["high"] == 0

    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SECRETS_SCAN
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.findings_count["medium"] == 1


def test_gitleaks_clean_scan_passes(sample_release: ReleaseContext) -> None:
    evidence = normalize_sarif(parse_sarif(REAL / "gitleaks" / "clean.sarif"), sample_release)
    assert evidence.evidence_type == EvidenceType.SECRETS_SCAN
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata == {}


def test_trivy_clean_report_without_results_is_recognised(tmp_path: Path) -> None:
    # Trivy 0.74.0 omits `Results` entirely when nothing was found.
    path = REAL / "trivy" / "clean.json"
    assert looks_like_trivy_json(json.loads(path.read_text(encoding="utf-8")))
    parsed = parse_trivy_json(path)
    assert parsed.groups == []
    release = ReleaseContext(release_id="1", commit_sha="abcdef1234567890")
    assert normalize_trivy_json(parsed, release) == []

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    shutil.copy(path, artifacts / "trivy.json")
    report = LocalArtifactCollector(release, artifacts_dirs=[artifacts]).collect()
    assert report.ignored == []
    assert report.errors == []
    assert report.evidence == []


def test_trivy_medium_secret_fails_the_secrets_scan() -> None:
    parsed = parse_trivy_json(REAL / "trivy" / "secret.json")
    release = ReleaseContext(release_id="1", commit_sha="abcdef1234567890")
    (evidence,) = normalize_trivy_json(parsed, release)
    assert evidence.evidence_type == EvidenceType.SECRETS_SCAN
    assert evidence.findings_count == {"medium": 1}
    assert evidence.status == EvidenceStatus.FAILED


def test_checkov_sarif_is_iac_evidence(sample_release: ReleaseContext) -> None:
    parsed = parse_sarif(REAL / "checkov" / "checkov.sarif")
    assert parsed.tool_name == "Checkov"
    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.IAC_SCAN
    assert evidence.classification is not None
    assert evidence.classification.reason == "driver_match"
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.findings_count["high"] == 10


def test_kics_sarif_resolves_rule_index_and_informational_kind(
    sample_release: ReleaseContext,
) -> None:
    # KICS v2.1.20 references rules by ruleIndex, sets no result level, and
    # marks five results kind "informational", whose level defaults to none.
    parsed = parse_sarif(REAL / "kics" / "kics.sarif")
    assert parsed.total_findings == 11
    assert parsed.findings_count == {"critical": 0, "high": 2, "medium": 3, "low": 1, "info": 5}

    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.IAC_SCAN
    assert evidence.status == EvidenceStatus.FAILED


def test_pytest_junit_counts(sample_release: ReleaseContext) -> None:
    parsed = parse_junit(REAL / "pytest" / "junit.xml")
    assert (parsed.total, parsed.failures, parsed.errors, parsed.skipped) == (4, 1, 1, 1)
    assert normalize_junit(parsed, sample_release).status == EvidenceStatus.FAILED
