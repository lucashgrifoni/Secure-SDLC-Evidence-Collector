"""Unit tests for normalizers."""

from __future__ import annotations

from pathlib import Path

from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.normalizers import (
    normalize_attestation,
    normalize_junit,
    normalize_pr_metadata,
    normalize_sarif,
    normalize_sbom,
    normalize_workflow_run,
)
from evidence_collector.parsers import (
    parse_attestation,
    parse_junit,
    parse_sarif,
    parse_sbom,
)


def test_normalize_sarif_classifies_sast(sample_release_root: Path, sample_release) -> None:
    parsed = parse_sarif(sample_release_root / "artifacts" / "semgrep.sarif")
    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SAST_SCAN
    assert evidence.status == EvidenceStatus.PASSED


def test_normalize_sarif_classifies_sca(sample_release_root: Path, sample_release) -> None:
    parsed = parse_sarif(sample_release_root / "artifacts" / "trivy.sarif")
    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SCA_SCAN


def test_normalize_sarif_classifies_secrets(sample_release_root: Path, sample_release) -> None:
    parsed = parse_sarif(sample_release_root / "artifacts" / "gitleaks.sarif")
    evidence = normalize_sarif(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SECRETS_SCAN
    assert evidence.status == EvidenceStatus.PASSED


def test_normalize_sbom(sample_release_root: Path, sample_release) -> None:
    parsed = parse_sbom(sample_release_root / "artifacts" / "sbom.cdx.json")
    evidence = normalize_sbom(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SBOM
    assert evidence.status == EvidenceStatus.GENERATED
    assert evidence.findings_count["components"] == 3


def test_normalize_junit(sample_release_root: Path, sample_release) -> None:
    parsed = parse_junit(sample_release_root / "artifacts" / "junit.xml")
    evidence = normalize_junit(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.TEST_RESULT
    assert evidence.status == EvidenceStatus.PASSED


def test_normalize_attestation(sample_release_root: Path, sample_release) -> None:
    parsed = parse_attestation(sample_release_root / "attestations" / "code_review.yaml")
    evidence = normalize_attestation(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.CODE_REVIEW
    assert evidence.manual is True


def test_normalize_pr_metadata_approved(sample_release) -> None:
    payload = {
        "number": 184,
        "reviewers_required": 2,
        "reviewers_approved": 2,
        "last_approval_after_last_commit": True,
        "html_url": "https://github.com/acme/payments-api/pull/184",
    }
    evidence = normalize_pr_metadata(payload, sample_release)
    assert evidence.evidence_type == EvidenceType.CODE_REVIEW
    assert evidence.status == EvidenceStatus.PASSED


def test_normalize_pr_metadata_not_enough_reviews(sample_release) -> None:
    payload = {
        "number": 185,
        "reviewers_required": 2,
        "reviewers_approved": 1,
        "last_approval_after_last_commit": False,
    }
    evidence = normalize_pr_metadata(payload, sample_release)
    assert evidence.status == EvidenceStatus.FAILED


def test_normalize_workflow_run_success(sample_release) -> None:
    evidence = normalize_workflow_run(
        {
            "run_id": 1001,
            "workflow_name": "ci.yml",
            "conclusion": "success",
            "html_url": "https://github.com/acme/payments-api/actions/runs/1001",
        },
        sample_release,
    )
    assert evidence.status == EvidenceStatus.PASSED
