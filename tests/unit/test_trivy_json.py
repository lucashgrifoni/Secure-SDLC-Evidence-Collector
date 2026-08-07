"""Tests for the native Trivy JSON parser (SchemaVersion 2).

The point of reading the native format is that one Trivy run produces
several *kinds* of finding at once, and the SARIF route collapses them
into a single evidence type. These tests pin that separation, the
SchemaVersion guard, and the class-name detail that prose gets wrong:
Trivy's misconfiguration class is literally ``config``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_trivy_json
from evidence_collector.parsers import parse_trivy_json
from evidence_collector.parsers._common import ParseError


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2.6.0", commit_sha="abcdef1234567890", branch="main")


def _report(**overrides: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "SchemaVersion": 2,
        "ArtifactName": "acme/api",
        "ArtifactType": "repository",
        "Metadata": {
            "ImageID": "sha256:image",
            "RepoDigests": ["acme/api@sha256:digest"],
            "OS": {"Family": "debian"},
        },
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-1", "Severity": "CRITICAL"},
                    {"VulnerabilityID": "CVE-2026-2", "Severity": "LOW"},
                ],
            },
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "DS026", "Severity": "LOW", "Status": "PASS"},
                ],
            },
            {
                "Target": ".env",
                "Class": "secret",
                "Secrets": [{"RuleID": "aws-access-key-id", "Severity": "CRITICAL"}],
            },
        ],
    }
    report.update(overrides)
    return report


def _write(directory: Path, payload: Any, name: str = "trivy.json") -> Path:
    target = directory / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# Class separation
# ---------------------------------------------------------------------------


def test_one_report_yields_three_groups(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    assert [g.kind for g in parsed.groups] == ["sca", "secrets", "iac"]


def test_misconfiguration_class_is_literally_config(tmp_path: Path) -> None:
    # Prose calls this "misconfiguration"; Trivy's ResultClass constant is
    # `config`. A parser written against the prose finds nothing.
    payload = _report()
    payload["Results"][1]["Class"] = "misconfiguration"
    parsed = parse_trivy_json(_write(tmp_path, payload))
    assert [g.kind for g in parsed.groups] == ["sca", "secrets"]


def test_passing_misconfigurations_are_not_counted(tmp_path: Path) -> None:
    # With --include-non-failures a report carries passed checks too.
    # Counting them would invent misconfigurations out of satisfied ones.
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    iac = next(g for g in parsed.groups if g.kind == "iac")
    assert iac.total == 1
    assert iac.ids == ["DS002"]


def test_severity_buckets(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    sca = next(g for g in parsed.groups if g.kind == "sca")
    assert sca.findings_count == {"critical": 1, "low": 1}


def test_unfamiliar_severity_counts_as_unknown(tmp_path: Path) -> None:
    payload = _report()
    payload["Results"][0]["Vulnerabilities"][0]["Severity"] = "SPICY"
    parsed = parse_trivy_json(_write(tmp_path, payload))
    sca = next(g for g in parsed.groups if g.kind == "sca")
    assert sca.findings_count == {"unknown": 1, "low": 1}


def test_license_and_custom_classes_are_read_past(tmp_path: Path) -> None:
    payload = _report()
    payload["Results"] = [
        {"Target": "x", "Class": "license", "Licenses": [{"Severity": "HIGH"}]},
        {"Target": "y", "Class": "license-file", "Licenses": [{"Severity": "HIGH"}]},
        {"Target": "z", "Class": "custom"},
        {"Target": "w", "Class": "unknown"},
    ]
    # Still a valid Trivy document, so it parses; there is simply no
    # evidence type whose meaning matches these classes, and inventing one
    # would be worse than declining.
    parsed = parse_trivy_json(_write(tmp_path, payload))
    assert parsed.groups == []
    assert normalize_trivy_json(parsed, _release()) == []


def test_metadata_digest_becomes_the_subject(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    assert parsed.repo_digest == "acme/api@sha256:digest"
    assert parsed.image_id == "sha256:image"


# ---------------------------------------------------------------------------
# SchemaVersion guard
# ---------------------------------------------------------------------------


def test_schema_version_3_is_rejected_with_a_diagnostic(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="SchemaVersion"):
        parse_trivy_json(_write(tmp_path, _report(SchemaVersion=3)))


def test_missing_schema_version_is_not_claimed(tmp_path: Path) -> None:
    payload = _report()
    del payload["SchemaVersion"]
    with pytest.raises(ParseError):
        parse_trivy_json(_write(tmp_path, payload))


def test_unrelated_json_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_trivy_json(_write(tmp_path, {"hello": "world"}))


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


def test_normalize_yields_one_evidence_per_class(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    evidences = normalize_trivy_json(parsed, _release())
    assert [e.evidence_type for e in evidences] == [
        EvidenceType.SCA_SCAN,
        EvidenceType.SECRETS_SCAN,
        EvidenceType.IAC_SCAN,
    ]


def test_evidence_ids_are_distinct_and_deterministic(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    first = [e.evidence_id for e in normalize_trivy_json(parsed, _release())]
    second = [e.evidence_id for e in normalize_trivy_json(parsed, _release())]
    assert first == second
    assert len(set(first)) == 3


def test_only_the_dependency_lane_carries_cve_ids(tmp_path: Path) -> None:
    # Secret rule ids and misconfiguration check ids are not CVEs and must
    # not be fed to EPSS/KEV enrichment as if they were.
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    by_type = {e.evidence_type: e for e in normalize_trivy_json(parsed, _release())}
    assert by_type[EvidenceType.SCA_SCAN].cve_ids == ["CVE-2026-1", "CVE-2026-2"]
    assert by_type[EvidenceType.SECRETS_SCAN].cve_ids == []
    assert by_type[EvidenceType.IAC_SCAN].cve_ids == []


def test_status_follows_blocking_severity(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    by_type = {e.evidence_type: e for e in normalize_trivy_json(parsed, _release())}
    # critical dependency finding, high misconfiguration, critical secret
    assert by_type[EvidenceType.SCA_SCAN].status == EvidenceStatus.FAILED
    assert by_type[EvidenceType.IAC_SCAN].status == EvidenceStatus.FAILED
    assert by_type[EvidenceType.SECRETS_SCAN].status == EvidenceStatus.FAILED


def test_non_blocking_class_passes(tmp_path: Path) -> None:
    payload = _report()
    payload["Results"] = [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-3", "Severity": "LOW"}],
        }
    ]
    parsed = parse_trivy_json(_write(tmp_path, payload))
    assert normalize_trivy_json(parsed, _release())[0].status == EvidenceStatus.PASSED


def test_empty_class_produces_no_evidence(tmp_path: Path) -> None:
    # "Trivy found no secrets" and "Trivy was not asked about secrets" are
    # different claims, and the report cannot tell them apart — so an empty
    # class must not become a vacuous PASSED.
    payload = _report()
    payload["Results"] = [{"Target": ".env", "Class": "secret", "Secrets": []}]
    parsed = parse_trivy_json(_write(tmp_path, payload))
    assert normalize_trivy_json(parsed, _release()) == []


def test_subject_ref_uses_the_repo_digest(tmp_path: Path) -> None:
    parsed = parse_trivy_json(_write(tmp_path, _report()))
    assert normalize_trivy_json(parsed, _release())[0].subject_ref == "acme/api@sha256:digest"


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


def test_collector_ingests_three_evidences_from_one_file(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _report(), name="trivy-report.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert sorted(e.evidence_type for e in report.evidence) == sorted(
        [EvidenceType.SCA_SCAN, EvidenceType.SECRETS_SCAN, EvidenceType.IAC_SCAN]
    )
    assert not report.errors


def test_collector_records_a_bad_schema_version_as_an_error(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _report(SchemaVersion=99), name="trivy-report.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert not report.evidence
    assert len(report.errors) == 1
    assert "SchemaVersion" in report.errors[0].reason
