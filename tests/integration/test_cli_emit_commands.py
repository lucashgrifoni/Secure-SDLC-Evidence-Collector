"""Integration coverage for the bundle-emitting CLI commands.

`test_cli_more_commands.py` covers compare/oscal/schema/plugins/doctor/
exceptions. This file fills in the four commands that take an existing
bundle and emit a derived artifact — they were the thinnest-covered part
of the CLI surface:

- `statement` — wrap a bundle as an in-toto Statement v1 (+ predicate-type
  validation and the optional DSSE envelope)
- `vex` — emit an OpenVEX document (+ bad --policy rejection)
- `guac` — emit a GUAC-collector container (+ malformed-bundle exit code)
- `enrich` — attach EPSS + CISA KEV intelligence (KEV/EPSS-empty path)

Tests use Typer's CliRunner to avoid spawning subprocesses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app
from evidence_collector.domain.models import EvidenceBundle


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def sample_bundle(runner: CliRunner, tmp_path: Path, sample_release_root: Path) -> Path:
    """Generate a sample bundle once and reuse it across the emit commands."""
    out = tmp_path / "sample"
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
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--output-dir",
            str(out),
            "--fail-on",
            "not_ready",
        ],
    )
    assert result.exit_code == 0, result.output
    return out / "bundle.json"


# ---------------------------------------------------------------------------
# statement
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_statement_writes_intoto_statement(
    runner: CliRunner, sample_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "statement.intoto.json"
    result = runner.invoke(app, ["statement", str(sample_bundle), "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    statement = json.loads(target.read_text(encoding="utf-8"))
    # in-toto Statement v1 carries _type, subject and predicateType.
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert "predicateType" in statement
    assert isinstance(statement["subject"], list) and statement["subject"]


@pytest.mark.integration
def test_statement_dsse_envelope_is_written_alongside(
    runner: CliRunner, sample_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "statement.intoto.json"
    result = runner.invoke(
        app,
        ["statement", str(sample_bundle), "--output", str(target), "--dsse-envelope"],
    )
    assert result.exit_code == 0, result.output
    envelope = target.with_suffix(".dsse.json")
    assert envelope.is_file()
    payload = json.loads(envelope.read_text(encoding="utf-8"))
    # A DSSE envelope has a base64 payload and a payloadType.
    assert "payload" in payload
    assert payload["payloadType"] == "application/vnd.in-toto+json"


@pytest.mark.integration
def test_statement_rejects_unknown_predicate_type(runner: CliRunner, sample_bundle: Path) -> None:
    result = runner.invoke(app, ["statement", str(sample_bundle), "--predicate-type", "bogus"])
    assert result.exit_code == 2
    assert "predicate-type" in result.output.lower() or "bogus" in result.output


# ---------------------------------------------------------------------------
# vex
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_vex_writes_openvex_document(
    runner: CliRunner, sample_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "openvex.json"
    result = runner.invoke(app, ["vex", str(sample_bundle), "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    document = json.loads(target.read_text(encoding="utf-8"))
    # OpenVEX documents carry an @context and a statements list.
    assert "@context" in document
    assert isinstance(document["statements"], list)


@pytest.mark.integration
def test_vex_rejects_invalid_policy(runner: CliRunner, sample_bundle: Path) -> None:
    result = runner.invoke(app, ["vex", str(sample_bundle), "--policy", "not-a-policy"])
    assert result.exit_code != 0
    assert "policy" in result.output.lower()


# ---------------------------------------------------------------------------
# guac
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_guac_writes_collection(runner: CliRunner, sample_bundle: Path, tmp_path: Path) -> None:
    target = tmp_path / "guac.json"
    result = runner.invoke(app, ["guac", str(sample_bundle), "-o", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    document = json.loads(target.read_text(encoding="utf-8"))
    assert "documents" in document
    assert isinstance(document["documents"], list)


@pytest.mark.integration
def test_guac_rejects_malformed_bundle(runner: CliRunner, tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")
    result = runner.invoke(app, ["guac", str(bad)])
    # Malformed JSON is a read/parse failure → exit code 2 per the contract.
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_enrich_writes_enriched_bundle_without_feeds(
    runner: CliRunner, sample_bundle: Path, tmp_path: Path
) -> None:
    target = tmp_path / "enriched.json"
    # No --epss-feed / --kev-feed: enrichment runs with empty feeds and must
    # still produce a schema-valid bundle (KEV/EPSS columns simply absent).
    result = runner.invoke(app, ["enrich", str(sample_bundle), "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    # The output must round-trip back into the bundle model unchanged in shape.
    enriched = EvidenceBundle.model_validate_json(target.read_text(encoding="utf-8"))
    assert enriched.summary is not None
