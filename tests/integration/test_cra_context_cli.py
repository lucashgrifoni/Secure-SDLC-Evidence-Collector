"""Exercise operator context through the public CLI, including failure streams."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.integration.test_cli_stream_contract import _run


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "sbom.json").write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}),
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(
        "controls:\n  - control_id: SBOM\n    framework: ORG_INTERNAL\n"
        "    name: Synthetic presence test\n    description: Local fixture only\n"
        "    criticality: high\n    required_evidence_types: [sbom]\n"
        "    recommended_evidence_types: []\n",
        encoding="utf-8",
    )
    context = tmp_path / "cra.json"
    context.write_text(
        json.dumps(
            {
                "release_id": "1",
                "commit_sha": "abcdef1234567890",
                "notification_type": "incident",
                "awareness_at": "2026-10-01T10:00:00Z",
                "notification_72h_submitted_at": "2026-10-03T10:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return artifacts, catalog, context


def test_context_produces_verified_release_metadata(tmp_path: Path) -> None:
    artifacts, catalog, context = _inputs(tmp_path)
    output = tmp_path / "output"
    result = _run(
        "run",
        "--application",
        "demo",
        "--repository",
        "demo/demo",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--artifacts-dir",
        str(artifacts),
        "--catalog",
        str(catalog),
        "--output-dir",
        str(output),
        "--profile",
        "cra-2026",
        "--cra-context",
        str(context),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads((output / "bundle.json").read_text(encoding="utf-8"))
    cra = payload["evidence"][0]["metadata"]["cra"]
    assert cra["reporting_deadlines"]["final_report"]["due_at"] == "2026-11-03T10:00:00+00:00"
    assert cra["submission_status"] == "not_submitted"
    assert _run("verify", str(output / "bundle.json")).returncode == 0


@pytest.mark.parametrize("change", ["release", "timezone", "extra", "chronology"])
@pytest.mark.parametrize("json_mode", [False, True])
def test_bad_context_is_rejected_without_partial_outputs(
    tmp_path: Path, change: str, json_mode: bool
) -> None:
    artifacts, catalog, context = _inputs(tmp_path)
    payload = json.loads(context.read_text(encoding="utf-8"))
    if change == "release":
        payload["release_id"] = "another"
    elif change == "timezone":
        payload["awareness_at"] = "2026-10-01T10:00:00"
    elif change == "chronology":
        payload["notification_72h_submitted_at"] = "2026-09-30T10:00:00Z"
    else:
        payload["unexpected"] = "PRIVATE-NARRATIVE-MARKER"
    context.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "output"
    prefix = ("--json-logs",) if json_mode else ()
    result = _run(
        *prefix,
        "run",
        "--application",
        "demo",
        "--repository",
        "demo/demo",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--artifacts-dir",
        str(artifacts),
        "--catalog",
        str(catalog),
        "--output-dir",
        str(output),
        "--profile",
        "cra-2026",
        "--cra-context",
        str(context),
    )
    assert result.returncode == 3
    assert not output.exists()
    assert "PRIVATE-NARRATIVE-MARKER" not in result.stdout + result.stderr
    if json_mode:
        events = [json.loads(line) for line in result.stdout.splitlines()]
        assert events and result.stderr == ""
    else:
        assert result.stdout == "" and result.stderr
    if change == "chronology":
        first_line = (result.stdout + result.stderr).splitlines()[0]
        assert "notification_72h_submitted_at" in first_line
        assert "awareness_at" in first_line


def _run_with(tmp_path: Path, *extra: str, commit_sha: str = "abcdef1234567890") -> Path:
    artifacts, catalog, _ = _inputs(tmp_path)
    output = tmp_path / "output"
    result = _run(
        "run",
        "--application",
        "demo",
        "--repository",
        "demo/demo",
        "--release-id",
        "1",
        "--commit-sha",
        commit_sha,
        "--artifacts-dir",
        str(artifacts),
        "--catalog",
        str(catalog),
        "--output-dir",
        str(output),
        *extra,
    )
    assert result.returncode == 0, result.stderr
    return output / "bundle.json"


def test_fedramp_class_is_case_insensitive(tmp_path: Path) -> None:
    bundle = _run_with(tmp_path, "--profile", "fedramp-20x", "--fedramp-class", "b")
    payload = json.loads(bundle.read_text(encoding="utf-8"))
    assert payload["evidence"][0]["metadata"]["fedramp"]["class"] == "B"


def test_context_sha_case_does_not_matter(tmp_path: Path) -> None:
    (tmp_path / "ctx").mkdir()
    _, _, context = _inputs(tmp_path / "ctx")
    bundle = _run_with(
        tmp_path,
        "--profile",
        "cra-2026",
        "--cra-context",
        str(context),
        commit_sha="ABCDEF1234567890",
    )
    assert bundle.is_file()
