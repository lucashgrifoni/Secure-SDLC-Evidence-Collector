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
from evidence_collector.domain.enums import ControlEvaluationStatus, EvidenceType
from evidence_collector.domain.models import Application, EvidenceBundle, Gap, ReleaseContext
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


def test_a_partial_control_names_the_recommended_evidence_it_lacks(gappy: Path) -> None:
    """A partial control has every required type; what it lacks is recommended."""
    bundle = _load(gappy)
    target = bundle.control_evaluations[0]
    partial = target.model_copy(
        update={
            "evaluation_status": ControlEvaluationStatus.PARTIAL,
            "missing_required_evidence_types": [],
            "missing_recommended_evidence_types": [EvidenceType.SBOM],
        }
    )
    bundle = bundle.model_copy(update={"control_evaluations": [partial]})
    [result] = build_gap_sarif(bundle)["runs"][0]["results"]
    assert "partial" in result["message"]["text"]
    assert "Missing recommended evidence: sbom." in result["message"]["text"]


def test_every_remediation_hint_for_a_control_reaches_the_rule(gappy: Path) -> None:
    bundle = _load(gappy)
    target = next(e for e in bundle.control_evaluations if e.evaluation_status.value == "missing")
    hints = [
        Gap(
            control_id=target.control_id,
            criticality=target.criticality,
            description="first gap",
            remediation="Attach the SBOM.",
        ),
        Gap(
            control_id=target.control_id,
            criticality=target.criticality,
            description="second gap",
            remediation="Attach the provenance.",
        ),
    ]
    bundle = bundle.model_copy(update={"gaps": hints})
    rules = build_gap_sarif(bundle)["runs"][0]["tool"]["driver"]["rules"]
    [rule] = [r for r in rules if r["id"] == target.control_id]
    assert "Attach the SBOM." in rule["help"]["text"]
    assert "Attach the provenance." in rule["help"]["text"]


def test_the_location_keeps_the_bundle_path_relative_to_the_working_directory(
    gappy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Code scanning resolves a location against the repository root."""
    nested = tmp_path / "output" / "release"
    nested.mkdir(parents=True)
    (nested / "bundle.json").write_bytes(gappy.read_bytes())
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["sarif", "output/release/bundle.json", "-o", "gaps.sarif"])
    assert result.exit_code == 0, result.output
    document = json.loads((tmp_path / "gaps.sarif").read_text(encoding="utf-8"))
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in document["runs"][0]["results"]
    }
    assert uris == {"output/release/bundle.json"}


def test_a_bundle_outside_the_working_directory_falls_back_to_its_name(
    gappy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    out = tmp_path / "gaps.sarif"
    result = CliRunner().invoke(app, ["sarif", str(gappy), "-o", str(out)])
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text(encoding="utf-8"))
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in document["runs"][0]["results"]
    }
    assert uris == {gappy.name}


def test_the_location_is_a_uri_even_when_the_path_has_spaces(
    gappy: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SARIF `artifactLocation.uri` is an RFC 3986 reference: no raw spaces."""
    nested = tmp_path / "release out" / "a&b#1"
    nested.mkdir(parents=True)
    (nested / "bundle.json").write_bytes(gappy.read_bytes())
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["sarif", "release out/a&b#1/bundle.json", "-o", "g.sarif"])
    assert result.exit_code == 0, result.output
    document = json.loads((tmp_path / "g.sarif").read_text(encoding="utf-8"))
    uris = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in document["runs"][0]["results"]
    }
    assert uris == {"release%20out/a%26b%231/bundle.json"}


def test_a_path_that_is_not_utf8_still_becomes_a_uri(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX file names can hold any byte; Python shows the odd ones as surrogates."""
    from evidence_collector.cli.commands.sarif import _artifact_uri

    monkeypatch.chdir(tmp_path)
    uri = _artifact_uri(Path("bad\udcffname") / "bundle.json")
    assert uri.isascii()
    assert uri.startswith("bad%")
    assert uri.endswith("name/bundle.json")
