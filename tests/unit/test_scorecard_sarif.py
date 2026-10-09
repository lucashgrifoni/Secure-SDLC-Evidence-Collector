"""OpenSSF Scorecard SARIF is repository posture, not static analysis.

Scorecard writes SARIF with ``tool.driver.name`` = ``Scorecard``. No token set
matched it, so the classifier fell back to ``sast_scan`` and, with no high or
critical result, recorded it as ``passed``: a Scorecard upload alone met
SSDF-PW.7 ("static analysis evidence"). No evidence type models Scorecard's
posture checks, so the collector now recognises the driver and does not turn
it into evidence: a Scorecard-only file is listed as an ignored artifact, and
in a merged file only the Scorecard run is dropped.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.controls import default_catalog
from evidence_collector.controls.engine import evaluate_control
from evidence_collector.domain.enums import ControlEvaluationStatus, EvidenceType
from evidence_collector.domain.models import ControlDefinition, ReleaseContext
from evidence_collector.normalizers import normalize_sarif
from evidence_collector.parsers import parse_sarif


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.10.09", commit_sha="abcdef1234567890")


def _run(driver: str, rule_id: str, level: str) -> dict[str, Any]:
    return {
        "tool": {
            "driver": {
                "name": driver,
                "informationUri": "https://github.com/ossf/scorecard",
                "rules": [{"id": rule_id, "shortDescription": {"text": rule_id}}],
            }
        },
        "results": [
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": "score is 3: branch protection not enabled"},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "no file associated"}}}
                ],
            }
        ],
    }


def _sarif(*runs: dict[str, Any]) -> str:
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": list(runs),
        }
    )


def _pw7() -> ControlDefinition:
    return next(c for c in default_catalog() if c.control_id == "SSDF-PW.7")


@pytest.mark.parametrize("driver", ["Scorecard", "scorecard", "OpenSSF Scorecard"])
def test_scorecard_only_sarif_is_ignored_not_sast(tmp_path: Path, driver: str) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "results.sarif").write_text(
        _sarif(_run(driver, "BranchProtectionID", "warning")), encoding="utf-8"
    )

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert report.evidence == []
    assert report.errors == []
    assert [p.name for p in report.ignored] == ["results.sarif"]
    evaluation, _gaps = evaluate_control(_pw7(), report.evidence)
    assert evaluation.evaluation_status is not ControlEvaluationStatus.MET


def test_merged_file_keeps_the_sast_run_and_drops_the_scorecard_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "merged.sarif").write_text(
        _sarif(
            _run("Scorecard", "BranchProtectionID", "warning"),
            _run("semgrep", "python.lang.security.audit.eval", "note"),
        ),
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert [e.producer for e in report.evidence] == ["semgrep"]
    assert report.evidence[0].evidence_type is EvidenceType.SAST_SCAN
    assert report.ignored == []
    assert "Scorecard" in caplog.text


def test_normalize_sarif_refuses_to_classify_scorecard(tmp_path: Path) -> None:
    path = tmp_path / "results.sarif"
    path.write_text(_sarif(_run("Scorecard", "PinnedDependenciesID", "warning")), encoding="utf-8")
    with pytest.raises(ValueError, match="Scorecard"):
        normalize_sarif(parse_sarif(path), _release())


def test_explicit_override_still_wins_for_scorecard(tmp_path: Path) -> None:
    path = tmp_path / "results.sarif"
    path.write_text(_sarif(_run("Scorecard", "PinnedDependenciesID", "warning")), encoding="utf-8")
    evidence = normalize_sarif(
        parse_sarif(path), _release(), evidence_type_override=EvidenceType.SCA_SCAN
    )
    assert evidence.evidence_type is EvidenceType.SCA_SCAN
    assert evidence.classification is not None
    assert evidence.classification.reason == "manual_override"
