"""`sdlc-evidence sarif`: unmet controls as SARIF 2.1.0 for a code scanning tab.

A bundle already says which controls a release did not meet, but only a
reader of `report.md` or `bundle.json` sees it. SARIF is what code scanning
dashboards ingest, so each unmet control becomes one result there. The
collector writes the file; uploading it is the caller's choice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.cli.main import app
from evidence_collector.domain.models import Application, EvidenceBundle, ReleaseContext
from evidence_collector.exporters.sarif_gaps import build_gap_sarif

_SAMPLE = Path("examples/sample_release")


def _bundle(tmp_path: Path, *, attestations: bool) -> Path:
    result = run_pipeline(
        Application(name="payments-api", repository="acme/payments-api"),
        ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main"),
        artifacts_dirs=[_SAMPLE / "artifacts"],
        attestations_dirs=[_SAMPLE / "attestations"] if attestations else [],
        output_dir=tmp_path / ("full" if attestations else "partial"),
    )
    assert result.json_path is not None
    return result.json_path


def _load(path: Path) -> EvidenceBundle:
    return EvidenceBundle.model_validate_json(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def gappy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _bundle(tmp_path_factory.mktemp("gappy"), attestations=False)


@pytest.fixture(scope="module")
def complete(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return _bundle(tmp_path_factory.mktemp("complete"), attestations=True)


def test_each_unmet_control_is_one_result(gappy: Path) -> None:
    bundle = _load(gappy)
    unmet = sorted(
        e.control_id
        for e in bundle.control_evaluations
        if e.evaluation_status.value in {"missing", "partial"}
    )
    document = build_gap_sarif(bundle)
    [run] = document["runs"]
    assert unmet, "the fixture should leave some controls unmet"
    assert [r["ruleId"] for r in run["results"]] == unmet
    assert sorted(rule["id"] for rule in run["tool"]["driver"]["rules"]) == unmet


def test_the_document_has_the_shape_code_scanning_requires(gappy: Path) -> None:
    document = build_gap_sarif(_load(gappy))
    assert document["version"] == "2.1.0"
    [run] = document["runs"]
    assert run["tool"]["driver"]["name"] == "secure-sdlc-evidence-collector"
    for result in run["results"]:
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        [location] = result["locations"]
        assert location["physicalLocation"]["artifactLocation"]["uri"]
        assert result["partialFingerprints"]["controlId/v1"] == result["ruleId"]


def test_level_follows_the_control_criticality(gappy: Path) -> None:
    bundle = _load(gappy)
    criticality = {e.control_id: e.criticality.value for e in bundle.control_evaluations}
    expected = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    [run] = build_gap_sarif(bundle)["runs"]
    assert {r["ruleId"]: r["level"] for r in run["results"]} == {
        r["ruleId"]: expected[criticality[r["ruleId"]]] for r in run["results"]
    }


def test_a_release_with_no_gaps_yields_no_results(complete: Path) -> None:
    [run] = build_gap_sarif(_load(complete))["runs"]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_the_output_is_byte_stable(gappy: Path) -> None:
    bundle = _load(gappy)
    first = json.dumps(build_gap_sarif(bundle), sort_keys=True)
    second = json.dumps(build_gap_sarif(bundle), sort_keys=True)
    assert first == second


def test_the_command_writes_the_file(gappy: Path, tmp_path: Path) -> None:
    out = tmp_path / "gaps.sarif"
    result = CliRunner().invoke(app, ["sarif", str(gappy), "-o", str(out)])
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["runs"][0]["results"]


@pytest.mark.parametrize("content", [None, "{not json", '{"bundle_id": "x"}'])
def test_a_missing_or_malformed_bundle_is_an_input_error(
    tmp_path: Path, content: str | None
) -> None:
    bundle = tmp_path / "bundle.json"
    if content is not None:
        bundle.write_text(content, encoding="utf-8")
    out = tmp_path / "gaps.sarif"
    result = CliRunner().invoke(app, ["sarif", str(bundle), "-o", str(out)])
    assert result.exit_code == 3
    assert not out.exists()
