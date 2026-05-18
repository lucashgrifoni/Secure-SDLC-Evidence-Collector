"""Tests for the --json-logs structured-output mode."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app


@pytest.mark.integration
def test_json_logs_emits_one_ndjson_line_per_event(
    tmp_path: Path, sample_release_root: Path
) -> None:
    runner = CliRunner()
    output_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "--json-logs",
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

    events: list[dict[str, object]] = []
    for line in result.output.splitlines():
        if not line.strip():
            continue
        # Skip the "Secure SDLC Evidence Collector v..." banner that
        # main() prints when stdout is a TTY. CliRunner sets a non-TTY
        # stdout, but we are defensive in case Typer's own announcements
        # leak through.
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    assert events, f"no JSON events parsed from output: {result.output!r}"
    bundle_event = next((e for e in events if e.get("event") == "bundle_built"), None)
    assert bundle_event is not None, f"missing bundle_built event in {events}"
    assert bundle_event["release_status"] == "ready"
    assert bundle_event["controls_met"] == 13
    assert bundle_event["coverage"] == 100
    evidence_count = bundle_event["evidence_count"]
    assert isinstance(evidence_count, int) and evidence_count >= 1


def test_json_logs_env_var_enables_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sample_release_root: Path
) -> None:
    monkeypatch.setenv("SDLC_JSON_LOGS", "1")
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
    parsed = [
        json.loads(line) for line in result.output.splitlines() if line.strip().startswith("{")
    ]
    assert any(
        e.get("event") == "bundle_built" for e in parsed
    ), f"SDLC_JSON_LOGS=1 should switch to JSON mode; got {result.output!r}"
