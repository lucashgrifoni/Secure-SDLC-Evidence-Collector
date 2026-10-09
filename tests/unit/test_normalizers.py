"""Unit tests for normalizers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.controls import default_catalog
from evidence_collector.controls.engine import evaluate_control
from evidence_collector.domain.enums import ControlEvaluationStatus, EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
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


def test_normalize_pr_metadata_stale_approvals_fail(sample_release) -> None:
    """Enough approvals that predate the last commit must not pass the review."""
    payload = {
        "number": 186,
        "reviewers_required": 2,
        "reviewers_approved": 2,
        "last_approval_after_last_commit": False,
    }
    evidence = normalize_pr_metadata(payload, sample_release)
    assert evidence.status == EvidenceStatus.FAILED
    control = next(c for c in default_catalog() if c.control_id == "ORG-CODE-REVIEW")
    evaluation, _gaps = evaluate_control(control, [evidence])
    assert evaluation.evaluation_status != ControlEvaluationStatus.MET


def test_normalize_pr_metadata_outstanding_change_request_fails(sample_release) -> None:
    payload = {
        "number": 187,
        "reviewers_required": 1,
        "reviewers_approved": 1,
        "last_approval_after_last_commit": True,
        "changes_requested": 1,
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


# ---------------------------------------------------------------------------
# Workflow runs: only a successful run is satisfying evidence. GitHub reports
# `conclusion: null` while a run is queued or in progress, and `skipped`,
# `neutral`, `action_required` and `stale` are not a pass either. All of them
# used to fall through to COMPLETED, which the control engine counts as
# satisfying, so OSPS-QA-03.01 ("status checks pass") was met by a run that
# had not finished, including the job that collects its own run id.
# ---------------------------------------------------------------------------

_NOT_A_PASS: list[dict[str, object]] = [
    {"conclusion": None, "status": "queued"},
    {"conclusion": None, "status": "in_progress"},
    {"status": "in_progress"},
    {"conclusion": "", "status": "waiting"},
    {"conclusion": "skipped", "status": "completed"},
    {"conclusion": "neutral", "status": "completed"},
    {"conclusion": "action_required", "status": "completed"},
    {"conclusion": "stale", "status": "completed"},
    {"conclusion": "something-new", "status": "completed"},
]


def _osps_qa_03_01():
    from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog

    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    return next(c for c in controls if c.control_id == "OSPS-QA-03.01")


@pytest.mark.parametrize("fields", _NOT_A_PASS, ids=lambda f: repr(f))
def test_normalize_workflow_run_unfinished_or_inconclusive_is_unknown(
    sample_release, fields: dict[str, object]
) -> None:
    payload = {"run_id": 1001, "workflow_name": "ci.yml", **fields}
    evidence = normalize_workflow_run(payload, sample_release)
    assert evidence.status is EvidenceStatus.UNKNOWN
    assert "none" not in evidence.summary.split("(")[0].lower()


@pytest.mark.parametrize("fields", _NOT_A_PASS, ids=lambda f: repr(f))
def test_osps_qa_03_01_is_not_met_by_a_run_that_did_not_succeed(
    sample_release, fields: dict[str, object]
) -> None:
    payload = {"run_id": 1001, "workflow_name": "ci.yml", **fields}
    evidence = normalize_workflow_run(payload, sample_release)
    evaluation, _gaps = evaluate_control(_osps_qa_03_01(), [evidence])
    assert evaluation.evaluation_status is not ControlEvaluationStatus.MET
    assert evaluation.evidence_refs == []


@pytest.mark.parametrize("conclusion", ["failure", "timed_out", "cancelled", "startup_failure"])
def test_normalize_workflow_run_failure_like_conclusions_stay_failed(
    sample_release, conclusion: str
) -> None:
    evidence = normalize_workflow_run(
        {"run_id": 1001, "workflow_name": "ci.yml", "conclusion": conclusion}, sample_release
    )
    assert evidence.status is EvidenceStatus.FAILED


def test_osps_qa_03_01_is_met_by_a_successful_run(sample_release) -> None:
    evidence = normalize_workflow_run(
        {"run_id": 1001, "workflow_name": "ci.yml", "conclusion": "success"}, sample_release
    )
    evaluation, _gaps = evaluate_control(_osps_qa_03_01(), [evidence])
    assert evaluation.evaluation_status is ControlEvaluationStatus.MET


# ---------------------------------------------------------------------------
# SARIF severity → evidence status (TST-01)
#
# `_sarif_status` maps critical/high findings to EvidenceStatus.FAILED. Nothing
# exercised the FAILED branch: patching the function to always return PASSED
# left the entire suite green. That branch matters — controls/engine.py treats
# PASSED as satisfying, so an inverted condition would let a SAST scan with
# critical findings satisfy SSDF-PW.7 and free the release, with every test
# still passing. Every sibling normalizer already asserts this convention
# (test_zap, test_normalizers/OSV, test_ai_normalizers, test_vsa); SARIF was
# the one gap.
# ---------------------------------------------------------------------------


def _sarif_with_severity(path: Path, *, level: str, security_severity: str) -> Path:
    path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "semgrep",
                                "version": "1.70.0",
                                "rules": [
                                    {
                                        "id": "rule-1",
                                        "properties": {"security-severity": security_severity},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "rule-1",
                                "level": level,
                                "message": {"text": "finding"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_normalize_sarif_marks_high_severity_findings_as_failed(
    tmp_path: Path, sample_release
) -> None:
    artifact = _sarif_with_severity(tmp_path / "high.sarif", level="error", security_severity="9.1")
    evidence = normalize_sarif(parse_sarif(artifact), sample_release)
    blocking = evidence.findings_count.get("critical", 0) + evidence.findings_count.get("high", 0)
    assert blocking > 0, f"fixture did not produce a blocking finding: {evidence.findings_count}"
    assert evidence.status == EvidenceStatus.FAILED


def test_normalize_sarif_marks_low_severity_findings_as_passed(
    tmp_path: Path, sample_release
) -> None:
    """The other half of the branch, so the test cannot pass by always-FAILED."""
    artifact = _sarif_with_severity(tmp_path / "low.sarif", level="note", security_severity="2.0")
    evidence = normalize_sarif(parse_sarif(artifact), sample_release)
    assert evidence.findings_count.get("critical", 0) + evidence.findings_count.get("high", 0) == 0
    assert evidence.status == EvidenceStatus.PASSED


def _junit(tmp_path: Path, **attrs: object) -> Path:
    rendered = " ".join(f'{key}="{value}"' for key, value in attrs.items())
    target = tmp_path / "junit.xml"
    target.write_text(f'<testsuite name="suite" {rendered}/>', encoding="utf-8")
    return target


@pytest.mark.parametrize(
    ("label", "tests", "skipped", "failures", "expected"),
    [
        ("nothing ran", 0, 0, 0, EvidenceStatus.INVALID),
        ("every test skipped", 5, 5, 0, EvidenceStatus.INVALID),
        ("some skipped, some ran", 5, 2, 0, EvidenceStatus.PASSED),
        ("all ran and passed", 5, 0, 0, EvidenceStatus.PASSED),
        ("a failure", 5, 0, 1, EvidenceStatus.FAILED),
    ],
)
def test_a_suite_that_never_ran_is_not_a_passing_test_run(
    tmp_path: Path,
    sample_release: ReleaseContext,
    label: str,
    tests: int,
    skipped: int,
    failures: int,
    expected: EvidenceStatus,
) -> None:
    """Zero failures out of zero tests used to certify the test-result control.

    It was recorded as `passed` at HIGH confidence and satisfied SSDF-PW.8
    outright. The trigger is not a hostile file: a test job whose glob matched
    nothing, a build that failed before the suite ran, a runner that wrote an
    empty report. Each of those produced a release certified as tested on the
    strength of a suite that never executed — the exact failure this tool
    exists to make impossible.

    `invalid` is the enum's value for "present but does not demonstrate what
    it claims", and the control engine does not count it as satisfying, so the
    control comes out MISSING with the file still visible to the auditor.
    """
    path = _junit(tmp_path, tests=tests, failures=failures, errors=0, skipped=skipped, time=1)

    evidence = normalize_junit(parse_junit(path), sample_release)

    assert evidence.status == expected, label


def test_an_empty_suite_says_why_it_proves_nothing(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    """The summary is what a human reads; silence there reads as a pass."""
    path = _junit(tmp_path, tests=0, failures=0, errors=0, skipped=0, time=0)

    evidence = normalize_junit(parse_junit(path), sample_release)

    assert evidence.summary is not None
    assert "no test actually ran" in evidence.summary


def test_the_summary_separates_reported_from_executed(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    """`42 tests executed ... 1 skipped` was self-contradictory: 41 executed."""
    path = _junit(tmp_path, tests=42, failures=0, errors=0, skipped=1, time=8)

    summary = normalize_junit(parse_junit(path), sample_release).summary

    assert summary is not None
    assert "42 tests reported" in summary
    assert "41 executed" in summary
