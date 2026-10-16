"""How a SARIF run becomes a scan evidence status.

* A run whose invocation reports ``executionSuccessful: false`` did not
  scan, so it is ``invalid`` and cannot satisfy a control.
* A run with no ``results`` array exported nothing: the status stays as
  computed, but confidence drops to low and a warning is logged.
* Any open result in a secrets scan fails it, whatever its level; the
  severity buckets stay as the scanner reported them.
* Accepted suppressions are counted apart and shown, not treated as open.
* IaC scanners (Checkov, KICS, tfsec, Terrascan) are ``iac_scan``.

New metadata keys appear only when their condition fires, so a plain run
produces the same record it always did.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.domain.enums import ConfidenceLevel, EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sarif
from evidence_collector.parsers import parse_sarif


def _evidence(tmp_path: Path, run: dict[str, Any], release: ReleaseContext) -> Any:
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}), encoding="utf-8")
    return normalize_sarif(parse_sarif(path), release)


def _run(name: str, results: list[Any] | None, **extra: Any) -> dict[str, Any]:
    run: dict[str, Any] = {"tool": {"driver": {"name": name}}, **extra}
    if results is not None:
        run["results"] = results
    return run


def test_failed_invocation_is_invalid_evidence(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    run = _run(
        "Semgrep OSS",
        None,
        invocations=[
            {
                "executionSuccessful": False,
                "exitCode": 2,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": "Fatal: could not parse config"}}
                ],
            }
        ],
    )
    evidence = _evidence(tmp_path, run, sample_release)
    assert evidence.status == EvidenceStatus.INVALID
    assert evidence.confidence == ConfidenceLevel.LOW
    assert evidence.metadata["execution_successful"] is False
    assert "did not complete" in evidence.summary


def test_failed_invocation_wins_over_results(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    # Results from a run that reports failure are partial at best.
    run = _run("semgrep", [{"level": "note"}], invocations=[{"executionSuccessful": False}])
    assert _evidence(tmp_path, run, sample_release).status == EvidenceStatus.INVALID


def test_absent_results_lower_confidence_and_warn(
    tmp_path: Path, sample_release: ReleaseContext, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="evidence_collector"):
        evidence = _evidence(tmp_path, _run("semgrep", None), sample_release)
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.LOW
    assert evidence.metadata == {"results_absent": True}
    assert any("no results array" in record.getMessage() for record in caplog.records)


def test_empty_results_keep_the_plain_record(
    tmp_path: Path, sample_release: ReleaseContext, caplog: pytest.LogCaptureFixture
) -> None:
    run = _run("semgrep", [], invocations=[{"executionSuccessful": True}])
    with caplog.at_level(logging.WARNING, logger="evidence_collector"):
        evidence = _evidence(tmp_path, run, sample_release)
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.HIGH
    assert evidence.metadata == {}
    assert evidence.summary == "semgrep reported 0 findings (high/critical=0)"
    assert not caplog.records


@pytest.mark.parametrize("level", ["note", "warning", "none"])
def test_any_secret_fails_the_secrets_scan(
    tmp_path: Path, sample_release: ReleaseContext, level: str
) -> None:
    evidence = _evidence(
        tmp_path, _run("gitleaks", [{"ruleId": "jwt", "level": level}]), sample_release
    )
    assert evidence.evidence_type == EvidenceType.SECRETS_SCAN
    assert evidence.status == EvidenceStatus.FAILED
    # Severity stays exactly as reported.
    assert evidence.findings_count["high"] == 0
    assert evidence.findings_count["critical"] == 0
    assert "any finding fails a secrets scan" in evidence.summary


def test_secrets_scan_with_only_accepted_suppressions_passes(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    result = {"ruleId": "jwt", "suppressions": [{"kind": "external", "status": "accepted"}]}
    evidence = _evidence(tmp_path, _run("gitleaks", [result]), sample_release)
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.metadata == {"suppressed_count": 1}


def test_a_secret_under_review_still_fails(tmp_path: Path, sample_release: ReleaseContext) -> None:
    result = {"ruleId": "jwt", "suppressions": [{"kind": "external", "status": "underReview"}]}
    evidence = _evidence(tmp_path, _run("gitleaks", [result]), sample_release)
    assert evidence.status == EvidenceStatus.FAILED


def test_accepted_suppression_of_an_error_does_not_fail_sast(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    # The pairing TST-02 asked for: a suppressed result whose rule defaults
    # to error must not turn a scan the tool calls clean into FAILED.
    run = {
        "tool": {
            "driver": {
                "name": "Semgrep OSS",
                "rules": [{"id": "r", "defaultConfiguration": {"level": "error"}}],
            }
        },
        "results": [{"ruleId": "r", "suppressions": [{"kind": "inSource"}]}],
    }
    evidence = _evidence(tmp_path, run, sample_release)
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.findings_count["high"] == 0
    assert evidence.metadata == {"suppressed_count": 1}
    assert evidence.summary == (
        "Semgrep OSS reported 0 findings (high/critical=0); 1 suppressed result(s) not counted"
    )


@pytest.mark.parametrize("driver", ["Checkov", "KICS v2.1.20", "tfsec", "terrascan"])
def test_iac_scanners_are_iac_evidence(
    tmp_path: Path, sample_release: ReleaseContext, driver: str
) -> None:
    evidence = _evidence(tmp_path, _run(driver, []), sample_release)
    assert evidence.evidence_type == EvidenceType.IAC_SCAN
    assert evidence.classification is not None
    assert evidence.classification.reason == "driver_match"
    assert evidence.evidence_id.startswith("iac-")
