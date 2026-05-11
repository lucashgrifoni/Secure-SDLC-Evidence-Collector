"""Unit tests for ``sdlc-evidence verify`` and the integrity helpers.

Coverage targets:

* ``application.integrity.normalize_bundle`` strips exactly the documented
  volatile fields and nothing else.
* ``application.integrity.structural_sha256`` produces a stable digest
  given a stable input.
* ``sdlc-evidence verify`` returns 0 on a match, 2 on drift, 3 on a
  malformed file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.application.integrity import (
    VOLATILE_CONTROL,
    VOLATILE_EVIDENCE,
    VOLATILE_TOP,
    normalize_bundle,
    structural_sha256,
)
from evidence_collector.cli.main import app


def _sample_bundle_dict() -> dict[str, object]:
    return {
        "bundle_id": "should-be-stripped",
        "generated_at": "2026-05-10T00:00:00Z",
        "release_status": "ready",
        "evidence": [
            {
                "evidence_id": "e1",
                "collected_at": "2026-05-10T00:00:00Z",
                "evidence_type": "sast_scan",
            }
        ],
        "control_evaluations": [
            {
                "control_id": "SSDF-PS.1",
                "evaluated_at": "2026-05-10T00:00:00Z",
                "status": "met",
            }
        ],
    }


def test_normalize_strips_top_level_volatile_fields() -> None:
    normalized = json.loads(normalize_bundle(_sample_bundle_dict()).decode("utf-8"))
    for key in VOLATILE_TOP:
        assert key not in normalized


def test_normalize_strips_nested_volatile_fields() -> None:
    normalized = json.loads(normalize_bundle(_sample_bundle_dict()).decode("utf-8"))
    assert all(key not in normalized["evidence"][0] for key in VOLATILE_EVIDENCE)
    assert all(key not in normalized["control_evaluations"][0] for key in VOLATILE_CONTROL)


def test_normalize_preserves_non_volatile_fields() -> None:
    normalized = json.loads(normalize_bundle(_sample_bundle_dict()).decode("utf-8"))
    assert normalized["release_status"] == "ready"
    assert normalized["evidence"][0]["evidence_id"] == "e1"
    assert normalized["evidence"][0]["evidence_type"] == "sast_scan"
    assert normalized["control_evaluations"][0]["control_id"] == "SSDF-PS.1"
    assert normalized["control_evaluations"][0]["status"] == "met"


def test_structural_sha256_is_stable_across_volatile_only_changes(tmp_path: Path) -> None:
    base = _sample_bundle_dict()
    other = _sample_bundle_dict()
    other["bundle_id"] = "completely-different"
    other["generated_at"] = "1999-01-01T00:00:00Z"
    other["evidence"][0]["collected_at"] = "1999-01-01T00:00:00Z"  # type: ignore[index]
    other["control_evaluations"][0]["evaluated_at"] = "1999-01-01T00:00:00Z"  # type: ignore[index]

    a_path = tmp_path / "a.json"
    b_path = tmp_path / "b.json"
    a_path.write_text(json.dumps(base), encoding="utf-8")
    b_path.write_text(json.dumps(other), encoding="utf-8")

    assert structural_sha256(a_path) == structural_sha256(b_path)


def test_structural_sha256_changes_when_a_non_volatile_field_changes(tmp_path: Path) -> None:
    base = _sample_bundle_dict()
    drifted = _sample_bundle_dict()
    drifted["release_status"] = "not_ready"

    a_path = tmp_path / "a.json"
    b_path = tmp_path / "b.json"
    a_path.write_text(json.dumps(base), encoding="utf-8")
    b_path.write_text(json.dumps(drifted), encoding="utf-8")

    assert structural_sha256(a_path) != structural_sha256(b_path)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def stable_bundle(tmp_path: Path) -> tuple[Path, str]:
    """Write a stable sample bundle and return (path, structural sha)."""
    payload = _sample_bundle_dict()
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")
    sha = hashlib.sha256(normalize_bundle(_sample_bundle_dict())).hexdigest()
    return bundle_path, sha


def test_verify_prints_digest_and_exits_zero_without_expected(
    runner: CliRunner, stable_bundle: tuple[Path, str]
) -> None:
    bundle_path, expected = stable_bundle
    result = runner.invoke(app, ["verify", str(bundle_path)])
    assert result.exit_code == 0
    assert expected in result.stdout


def test_verify_exits_zero_on_match(runner: CliRunner, stable_bundle: tuple[Path, str]) -> None:
    bundle_path, sha = stable_bundle
    result = runner.invoke(app, ["verify", str(bundle_path), "--expected", sha])
    assert result.exit_code == 0


def test_verify_exits_two_on_drift(runner: CliRunner, stable_bundle: tuple[Path, str]) -> None:
    bundle_path, _ = stable_bundle
    result = runner.invoke(
        app,
        [
            "verify",
            str(bundle_path),
            "--expected",
            "0" * 64,
        ],
    )
    assert result.exit_code == 2


def test_verify_exits_three_on_malformed_json(runner: CliRunner, tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{this is not json", encoding="utf-8")
    result = runner.invoke(app, ["verify", str(bad)])
    assert result.exit_code == 3
