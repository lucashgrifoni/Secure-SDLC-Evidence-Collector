"""The collector's own gap SARIF is a report about evidence, not scan evidence.

`sdlc-evidence sarif` writes unmet controls as SARIF with ``tool.driver.name``
set to the collector's own name. No token set matched that name, so when the
file landed in a later ``--artifacts-dir`` the classifier fell back to
``sast_scan``. A gap log from a ready release has no results, so it became a
``passed`` SAST scan, met SSDF-PW.7 and SAMM-VERIF-ST-1, and moved a release
with no SAST evidence from conditional to ready. The collector now recognises
its own driver and lists such a file as ignored, as it does for Scorecard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.controls import default_catalog
from evidence_collector.controls.engine import evaluate_control
from evidence_collector.domain.enums import ControlEvaluationStatus, EvidenceType
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    EvidenceBundle,
    ReleaseContext,
)
from evidence_collector.exporters.sarif_gaps import TOOL_NAME, build_gap_sarif
from evidence_collector.normalizers import normalize_sarif
from evidence_collector.parsers import parse_sarif

_SAMPLE = Path("examples/sample_release")


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


@pytest.fixture(scope="module")
def gap_sarif(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """A gap SARIF the exporter really wrote, for a bundle with unmet controls."""
    result = run_pipeline(
        Application(name="payments-api", repository="acme/payments-api"),
        _release(),
        artifacts_dirs=[_SAMPLE / "artifacts"],
        attestations_dirs=[],
        output_dir=tmp_path_factory.mktemp("gaps"),
    )
    assert result.json_path is not None
    bundle = EvidenceBundle.model_validate_json(result.json_path.read_text(encoding="utf-8"))
    document = build_gap_sarif(bundle)
    assert document["runs"][0]["tool"]["driver"]["name"] == TOOL_NAME
    assert document["runs"][0]["results"], "the fixture should leave some controls unmet"
    return document


def _empty(document: dict[str, Any]) -> dict[str, Any]:
    """The same log as a ready release produces it: no rules, no results."""
    run = json.loads(json.dumps(document["runs"][0]))
    run["tool"]["driver"]["rules"] = []
    run["results"] = []
    return {**document, "runs": [run]}


def _pw7() -> ControlDefinition:
    return next(c for c in default_catalog() if c.control_id == "SSDF-PW.7")


@pytest.mark.parametrize("shape", ["ready", "unmet"])
def test_own_gap_sarif_is_ignored_not_sast(
    tmp_path: Path, gap_sarif: dict[str, Any], shape: str
) -> None:
    document = _empty(gap_sarif) if shape == "ready" else gap_sarif
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "gaps.sarif").write_text(json.dumps(document), encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert report.evidence == []
    assert report.errors == []
    assert [p.name for p in report.ignored] == ["gaps.sarif"]
    evaluation, _gaps = evaluate_control(_pw7(), report.evidence)
    assert evaluation.evaluation_status is ControlEvaluationStatus.MISSING


def test_merged_file_keeps_the_scanner_run_and_drops_the_gap_run(
    tmp_path: Path, gap_sarif: dict[str, Any]
) -> None:
    semgrep = json.loads((_SAMPLE / "artifacts" / "semgrep.sarif").read_text(encoding="utf-8"))
    merged = {**semgrep, "runs": [_empty(gap_sarif)["runs"][0], *semgrep["runs"]]}
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "merged.sarif").write_text(json.dumps(merged), encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert [e.evidence_type for e in report.evidence] == [EvidenceType.SAST_SCAN]
    assert TOOL_NAME not in {e.producer for e in report.evidence}
    assert report.ignored == []


def test_normalize_sarif_refuses_to_classify_its_own_gap_log(
    tmp_path: Path, gap_sarif: dict[str, Any]
) -> None:
    path = tmp_path / "gaps.sarif"
    path.write_text(json.dumps(_empty(gap_sarif)), encoding="utf-8")
    with pytest.raises(ValueError, match=TOOL_NAME):
        normalize_sarif(parse_sarif(path), _release())


def test_a_ready_release_cannot_be_reached_with_an_old_gap_log(
    tmp_path: Path, gap_sarif: dict[str, Any]
) -> None:
    """The reported loop: sample artifacts without semgrep, plus an empty gap log."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    for source in (_SAMPLE / "artifacts").iterdir():
        if source.name != "semgrep.sarif":
            (artifacts / source.name).write_bytes(source.read_bytes())
    (artifacts / "gaps.sarif").write_text(json.dumps(_empty(gap_sarif)), encoding="utf-8")

    result = run_pipeline(
        Application(name="payments-api", repository="acme/payments-api"),
        _release(),
        artifacts_dirs=[artifacts],
        attestations_dirs=[_SAMPLE / "attestations"],
        output_dir=tmp_path / "out",
    )

    assert result.json_path is not None
    bundle = EvidenceBundle.model_validate_json(result.json_path.read_text(encoding="utf-8"))
    assert EvidenceType.SAST_SCAN not in {e.evidence_type for e in bundle.evidence}
    assert "SSDF-PW.7:sast_scan" in bundle.summary.missing_critical_evidence
