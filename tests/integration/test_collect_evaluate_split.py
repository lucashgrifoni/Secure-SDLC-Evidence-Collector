"""The documented `collect` -> `evaluate` split must not lose the failures.

`collect` wrote a bare JSON list of evidence records. A list has nowhere to
carry the inputs the collector could not read, so the split path dropped them
at the boundary: the console warned, the file said nothing, and the bundle
built from it asserted `"collection_errors": []` — a positive claim that
nothing had failed to parse, on the very artifact meant to be the durable
record.

`run` was fixed earlier in this branch; this pins the other half of the flow
the README documents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _sarif() -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
                    "results": [],
                }
            ],
        }
    )


def _artifacts(tmp_path: Path, *, broken: bool) -> Path:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "good.sarif").write_text(_sarif(), encoding="utf-8")
    if broken:
        (artifacts / "truncated.sarif").write_text('{"runs": [ trunc', encoding="utf-8")
    return artifacts


def _collect(runner: CliRunner, artifacts: Path, out: Path) -> None:
    result = runner.invoke(
        app,
        [
            "collect",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(artifacts),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output


def _evaluate(runner: CliRunner, evidence: Path, out_dir: Path) -> None:
    runner.invoke(
        app,
        [
            "evaluate",
            "--evidence",
            str(evidence),
            "--application",
            "demo",
            "--repository",
            "acme/demo",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--output-dir",
            str(out_dir),
        ],
    )


@pytest.mark.integration
def test_collect_persists_the_inputs_it_could_not_read(runner: CliRunner, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    _collect(runner, _artifacts(tmp_path, broken=True), evidence)

    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert isinstance(payload, dict), "collect must write an envelope, not a bare list"
    assert len(payload["collection_errors"]) == 1
    assert payload["collection_errors"][0]["path"].endswith("truncated.sarif")
    assert len(payload["evidence"]) == 1


@pytest.mark.integration
def test_evaluate_carries_them_into_the_bundle(runner: CliRunner, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    _collect(runner, _artifacts(tmp_path, broken=True), evidence)
    _evaluate(runner, evidence, tmp_path / "out")

    bundle = json.loads((tmp_path / "out" / "bundle.json").read_text(encoding="utf-8"))
    assert len(bundle["collection_errors"]) == 1
    assert "truncated.sarif" in bundle["collection_errors"][0]["path"]
    # And it must reach the human-facing artifact too.
    assert "truncated.sarif" in (tmp_path / "out" / "report.md").read_text(encoding="utf-8")


@pytest.mark.integration
def test_a_clean_collect_reports_nothing(runner: CliRunner, tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    _collect(runner, _artifacts(tmp_path, broken=False), evidence)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    assert payload["collection_errors"] == []

    _evaluate(runner, evidence, tmp_path / "out")
    bundle = json.loads((tmp_path / "out" / "bundle.json").read_text(encoding="utf-8"))
    # The bundle is the published contract and its schema is
    # `additionalProperties: false`, so a clean run omits the key entirely
    # rather than shipping an empty list a 1.0.0 consumer would reject.
    assert "collection_errors" not in bundle


@pytest.mark.integration
def test_a_legacy_bare_list_evidence_file_still_evaluates(
    runner: CliRunner, tmp_path: Path
) -> None:
    """Files written by earlier versions must keep working.

    They can say nothing about failed inputs — that is the limitation the
    envelope exists to remove — but they must not become unreadable.
    """
    evidence = tmp_path / "evidence.json"
    _collect(runner, _artifacts(tmp_path, broken=False), evidence)
    envelope = json.loads(evidence.read_text(encoding="utf-8"))
    evidence.write_text(json.dumps(envelope["evidence"]), encoding="utf-8")

    _evaluate(runner, evidence, tmp_path / "out")
    bundle = json.loads((tmp_path / "out" / "bundle.json").read_text(encoding="utf-8"))
    assert len(bundle["evidence"]) == 1
    assert "collection_errors" not in bundle
