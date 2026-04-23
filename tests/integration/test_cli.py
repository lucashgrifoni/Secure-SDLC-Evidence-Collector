"""CLI integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app


@pytest.mark.integration
def test_cli_run_on_sample_release(tmp_path: Path, sample_release_root: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--branch",
            "main",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--output-dir",
            str(output_dir),
            "--fail-on",
            "not_ready",
        ],
    )
    assert result.exit_code == 0, result.output
    bundle_path = output_dir / "bundle.json"
    assert bundle_path.is_file()
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert payload["summary"]["release_status"] == "ready"


@pytest.mark.integration
def test_cli_run_blocks_not_ready(tmp_path: Path, sample_release_root: Path) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--output-dir",
            str(output_dir),
            "--fail-on",
            "not_ready",
        ],
    )
    assert result.exit_code == 2, result.output


@pytest.mark.integration
def test_cli_controls_command() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["controls"])
    assert result.exit_code == 0
    assert "SSDF-PS.3" in result.output
