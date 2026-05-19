"""Unit tests for normalizers."""

from __future__ import annotations

from pathlib import Path

from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.normalizers import (
    normalize_attestation,
    normalize_junit,
    normalize_osv,
    normalize_pr_metadata,
    normalize_sarif,
    normalize_sbom,
    normalize_workflow_run,
)
from evidence_collector.parsers import (
    parse_attestation,
    parse_junit,
    parse_osv,
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
    # T6.1: a 1.5 SBOM has no lifecycles or inline analyses, so those
    # metadata keys must be absent (not set to empty list) to preserve
    # byte-stability for bundles produced before T6.1.
    assert "lifecycle_phases" not in evidence.metadata
    assert "sbom_vex_analyses" not in evidence.metadata


def test_normalize_osv_maps_to_sca_scan_with_ecosystems(tmp_path: Path, sample_release) -> None:
    osv_path = tmp_path / "osv-scanner.json"
    osv_path.write_text(
        """
        {
          "results": [
            {
              "packages": [
                {
                  "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                  "vulnerabilities": [
                    {
                      "id": "GHSA-p6mc-m468-83gw",
                      "aliases": ["CVE-2020-8203"],
                      "severity": [{"type": "CVSS_V3", "score": "7.4"}]
                    }
                  ]
                }
              ]
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_osv(osv_path)
    evidence = normalize_osv(parsed, sample_release)
    assert evidence.evidence_type == EvidenceType.SCA_SCAN
    # Critical/high finding → blocking → FAILED status (matches the
    # convention used by normalize_zap and normalize_sarif).
    assert evidence.status == EvidenceStatus.FAILED
    assert evidence.metadata["ecosystems"] == ["npm"]
    assert evidence.metadata["affected_package_count"] == 1
    assert evidence.cve_ids == ["CVE-2020-8203"]


def test_normalize_sbom_carries_cyclonedx_17_metadata(tmp_path: Path, sample_release) -> None:
    sbom_path = tmp_path / "sbom-1.7.cdx.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.7",
          "serialNumber": "urn:uuid:1faaaaa0-1111-2222-3333-444444444444",
          "version": 1,
          "metadata": {
            "component": {"type": "application", "name": "api", "purl": "pkg:generic/acme/api@1"},
            "lifecycles": [{"phase": "build"}, {"phase": "operations"}]
          },
          "components": [],
          "vulnerabilities": [
            {
              "id": "CVE-2026-1111",
              "analysis": {"state": "not_affected", "justification": "code_not_reachable"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_sbom(sbom_path)
    evidence = normalize_sbom(parsed, sample_release)
    assert evidence.metadata["lifecycle_phases"] == ["build", "operations"]
    analyses = evidence.metadata["sbom_vex_analyses"]
    assert len(analyses) == 1
    assert analyses[0]["cve_id"] == "CVE-2026-1111"
    assert analyses[0]["state"] == "not_affected"


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
