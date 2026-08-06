"""Integration coverage for CLI commands not exercised by `test_cli.py`.

`test_cli.py` covers `run` (positive + negative) and `controls`. This
file fills in the remaining surface used by docs and CI:

- `compare` — JSON output and exit-code contract
- `oscal --output` — file gets written and parses as JSON
- `schema --output` — file gets written and is a valid JSON Schema doc
- `plugins` — lists at least the built-in parsers and collectors
- `doctor --json` — emits machine-readable health checks
- `exceptions validate` and `exceptions list` — happy path + invalid file

Tests use Typer's CliRunner to avoid spawning subprocesses.
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


@pytest.fixture
def sample_bundle(runner: CliRunner, tmp_path: Path, sample_release_root: Path) -> Path:
    """Generate a sample bundle once and reuse for compare/oscal/etc."""
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
# compare
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_compare_emits_zero_delta_for_identical_bundles(
    runner: CliRunner, sample_bundle: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "compare",
            str(sample_bundle),
            str(sample_bundle),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["coverage_delta"] == 0
    assert payload["confidence_delta"] == 0
    assert payload["before_release_status"] == payload["after_release_status"]
    controls = payload["controls"]
    assert controls["added"] == []
    assert controls["removed"] == []
    assert controls["improved"] == []
    assert controls["regressed"] == []
    assert len(controls["unchanged"]) == 13


@pytest.mark.integration
def test_compare_table_format_does_not_emit_json(runner: CliRunner, sample_bundle: Path) -> None:
    """The default (non-`--format json`) output is a Rich table; the test
    just asserts the exit code and that the output is *not* JSON.
    """
    result = runner.invoke(app, ["compare", str(sample_bundle), str(sample_bundle)])
    assert result.exit_code == 0, result.output
    # The first non-whitespace character must not be `{` (JSON object) or
    # `[` (JSON array) — Rich tables start with box-drawing characters.
    stripped = result.output.lstrip()
    assert not stripped.startswith(("{", "["))


# ---------------------------------------------------------------------------
# oscal
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_oscal_writes_valid_json_to_output_path(runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "catalog.json"
    result = runner.invoke(app, ["oscal", "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    payload = json.loads(target.read_text(encoding="utf-8"))
    # OSCAL Catalog has a top-level `catalog` object with `metadata`.
    assert "catalog" in payload
    assert "metadata" in payload["catalog"]
    # We expect the 13 controls to appear under groups/controls.
    serialized = json.dumps(payload)
    assert "SSDF-PS.3" in serialized
    assert "ORG-CODE-REVIEW" in serialized


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_schema_writes_valid_json_schema_to_output_path(runner: CliRunner, tmp_path: Path) -> None:
    target = tmp_path / "bundle.schema.json"
    result = runner.invoke(app, ["schema", "--output", str(target)])
    assert result.exit_code == 0, result.output
    assert target.is_file()
    schema = json.loads(target.read_text(encoding="utf-8"))
    # JSON Schema documents have `$schema` and `properties` (or
    # `$defs` / `$ref`). Pydantic uses Draft 2020-12 by default.
    assert "$schema" in schema or "$defs" in schema or "properties" in schema
    # The generated schema must reference the bundle title or a known
    # property; we sanity-check on a key the bundle always has.
    serialized = json.dumps(schema)
    assert "control_evaluations" in serialized or "ControlEvaluation" in serialized


# ---------------------------------------------------------------------------
# plugins
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_plugins_lists_builtin_parsers_and_collectors(runner: CliRunner) -> None:
    result = runner.invoke(app, ["plugins"])
    assert result.exit_code == 0, result.output
    # All six built-in parsers and three collectors must appear.
    for token in (
        "attestation",
        "exception",
        "junit",
        "sarif",
        "sbom",
        "zap",
        "github",
        "gitlab",
        "local",
    ):
        assert token in result.output, f"plugin {token!r} missing from output"


# ---------------------------------------------------------------------------
# doctor --json
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_doctor_json_emits_check_array(runner: CliRunner) -> None:
    result = runner.invoke(app, ["doctor", "--json"])
    # doctor exits 0 in healthy CI; even when optional checks fail it must
    # still emit valid JSON.
    payload = json.loads(result.output)
    assert "checks" in payload
    checks = payload["checks"]
    assert isinstance(checks, list)
    assert len(checks) >= 5
    for check in checks:
        assert "check" in check
        assert "ok" in check
        assert isinstance(check["ok"], bool)


# ---------------------------------------------------------------------------
# exceptions validate / list
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_exceptions_validate_accepts_demo_fixture(runner: CliRunner) -> None:
    fixture = (
        Path(__file__).resolve().parents[2]
        / "examples"
        / "sample_release"
        / "exceptions"
        / "EXC-2026-DEMO-001.yaml"
    )
    assert fixture.is_file()
    result = runner.invoke(app, ["exceptions", "validate", str(fixture)])
    assert result.exit_code == 0, result.output
    assert "EXC-2026-DEMO-001" in result.output
    assert "valid" in result.output


@pytest.mark.integration
def test_exceptions_validate_rejects_missing_required_fields(
    runner: CliRunner, tmp_path: Path
) -> None:
    bad = tmp_path / "missing-fields.yaml"
    bad.write_text(
        # justification missing → ParseError
        "exception_id: 'EXC-X'\n"
        "control_id: 'SSDF-PW.1'\n"
        "approver: 'a@example.com'\n"
        "approved_at: '2026-05-05T00:00:00Z'\n"
        "expires_at: '2026-08-05T00:00:00Z'\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["exceptions", "validate", str(bad)])
    # Validate should reject and exit non-zero.
    assert result.exit_code != 0
    # Output should mention the missing field "justification" or
    # "required" so the operator sees what's wrong.
    assert "justification" in result.output.lower() or "required" in result.output.lower()


@pytest.mark.integration
def test_exceptions_validate_accepts_multiple_files(runner: CliRunner) -> None:
    # pre-commit passes every matched, staged file in a single invocation,
    # so validate must accept more than one path and pass when all are valid.
    fixtures_dir = (
        Path(__file__).resolve().parents[2] / "examples" / "sample_release" / "exceptions"
    )
    yaml_files = [str(p) for p in sorted(fixtures_dir.glob("*.yaml"))]
    assert yaml_files, "expected at least one demo waiver fixture"
    result = runner.invoke(app, ["exceptions", "validate", *yaml_files])
    assert result.exit_code == 0, result.output
    assert "valid" in result.output


@pytest.mark.integration
def test_exceptions_validate_one_invalid_among_many_exits_nonzero(
    runner: CliRunner, tmp_path: Path
) -> None:
    # A mixed batch (one valid, one malformed) must fail: the exit code is
    # what makes this usable as a pre-commit gate.
    good = (
        Path(__file__).resolve().parents[2]
        / "examples"
        / "sample_release"
        / "exceptions"
        / "EXC-2026-DEMO-001.yaml"
    )
    bad = tmp_path / "broken.yaml"
    bad.write_text(
        "exception_id: 'EXC-BROKEN'\ncontrol_id: 'SSDF-PW.1'\n",  # missing required fields
        encoding="utf-8",
    )
    result = runner.invoke(app, ["exceptions", "validate", str(good), str(bad)])
    assert result.exit_code == 1, result.output
    # The valid one is still reported, and the invalid one is named.
    assert "EXC-2026-DEMO-001" in result.output
    assert "broken.yaml" in result.output


@pytest.mark.integration
def test_exceptions_validate_with_no_paths_exits_usage_error(runner: CliRunner) -> None:
    # No paths is operator misuse (pre-commit never calls a files-gated hook
    # with zero matches). Surface it rather than silently passing.
    result = runner.invoke(app, ["exceptions", "validate"])
    assert result.exit_code != 0


@pytest.mark.integration
def test_exceptions_list_walks_directory_and_counts_validity(
    runner: CliRunner, tmp_path: Path
) -> None:
    fixtures_dir = (
        Path(__file__).resolve().parents[2] / "examples" / "sample_release" / "exceptions"
    )
    assert fixtures_dir.is_dir()
    result = runner.invoke(app, ["exceptions", "list", str(fixtures_dir)])
    assert result.exit_code == 0, result.output
    # The README is markdown, not YAML — only the YAML file should count.
    #
    # This used to assert `1 valid · 0 invalid`. "valid" meant "parsed", so an
    # *expired* waiver — one that waives nothing — was reported as valid, which
    # is the opposite of what a reader needs from a command that ships as a
    # pre-commit hook. The counters now separate the two, and expiry has its own
    # column. The demo fixture is in-date, so it counts as active.
    assert "1 active" in result.output
    assert "0 expired" in result.output
    assert "0 unparseable" in result.output
    # The Rich table truncates long IDs to fit terminal width (`EXC-2026-DEM…`),
    # so assert on a stable prefix instead of the full ID.
    assert "EXC-2026-DEM" in result.output


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_version_flag_prints_version_and_exits(runner: CliRunner) -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    # Version is read from src/evidence_collector/__init__.py, currently 1.1.0.
    # We only assert the format (major.minor.patch) so this test does not
    # need updating on every bump.
    output = result.output.strip()
    parts = output.split(".")
    assert len(parts) == 3, f"expected semver-like x.y.z, got {output!r}"
    assert all(part.isdigit() for part in parts), f"non-numeric version: {output!r}"
