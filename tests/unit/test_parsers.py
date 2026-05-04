"""Unit tests for parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.parsers import (
    parse_attestation,
    parse_junit,
    parse_sarif,
    parse_sbom,
)
from evidence_collector.parsers._common import ParseError


def test_parse_sarif_semgrep(sample_release_root: Path) -> None:
    parsed = parse_sarif(sample_release_root / "artifacts" / "semgrep.sarif")
    assert parsed.tool_name == "semgrep"
    assert parsed.total_findings == 2
    assert parsed.findings_count["medium"] == 1
    assert parsed.findings_count["low"] == 1
    assert parsed.findings_count["high"] == 0
    assert parsed.artifact.integrity_hash.startswith("sha256:")


def test_parse_sarif_requires_runs(tmp_path: Path) -> None:
    empty = tmp_path / "empty.sarif"
    empty.write_text('{"version":"2.1.0"}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_sarif(empty)


def test_parse_sbom_cyclonedx(sample_release_root: Path) -> None:
    parsed = parse_sbom(sample_release_root / "artifacts" / "sbom.cdx.json")
    assert parsed.format == "cyclonedx"
    assert parsed.component_count == 3
    assert parsed.subject_ref == "pkg:generic/acme/payments-api@2026.04.10"
    assert parsed.spec_version == "1.5"


def test_parse_sbom_spdx(tmp_path: Path) -> None:
    spdx_path = tmp_path / "spdx.json"
    spdx_path.write_text(
        '{"spdxVersion":"SPDX-2.3","name":"acme/payments-api",'
        '"documentNamespace":"urn:uuid:123","packages":[{"name":"foo"}]}',
        encoding="utf-8",
    )
    parsed = parse_sbom(spdx_path)
    assert parsed.format == "spdx"
    assert parsed.spec_version == "SPDX-2.3"
    assert parsed.component_count == 1


def test_parse_junit(sample_release_root: Path) -> None:
    parsed = parse_junit(sample_release_root / "artifacts" / "junit.xml")
    assert parsed.total == 42
    assert parsed.failures == 0
    assert parsed.errors == 0
    assert parsed.skipped == 1
    assert parsed.suite_name == "payments-api-suite"


def test_parse_attestation_yaml(sample_release_root: Path) -> None:
    parsed = parse_attestation(sample_release_root / "attestations" / "release_approval.yaml")
    assert parsed.evidence_type.value == "release_approval"
    assert parsed.producer == "Change Advisory Board"
    assert parsed.metadata.get("change_ticket") == "CHG-1234"


def test_parse_attestation_rejects_missing_fields(tmp_path: Path) -> None:
    bad_path = tmp_path / "bad.yaml"
    bad_path.write_text("evidence_type: sast_scan\n", encoding="utf-8")
    with pytest.raises(ParseError):
        parse_attestation(bad_path)


def test_parse_junit_rejects_malformed_xml(tmp_path: Path) -> None:
    bad = tmp_path / "broken.xml"
    bad.write_text("<testsuite tests='1'><testcase></testsuite>", encoding="utf-8")
    with pytest.raises(ParseError, match="Invalid JUnit XML"):
        parse_junit(bad)


def test_parse_junit_rejects_unknown_root(tmp_path: Path) -> None:
    bad = tmp_path / "wrong_root.xml"
    bad.write_text("<results><testcase /></results>", encoding="utf-8")
    with pytest.raises(ParseError, match="Unexpected JUnit root element"):
        parse_junit(bad)


def test_parse_junit_rejects_empty_testsuites(tmp_path: Path) -> None:
    empty = tmp_path / "empty_testsuites.xml"
    empty.write_text("<testsuites></testsuites>", encoding="utf-8")
    with pytest.raises(ParseError, match="no test suites"):
        parse_junit(empty)


def test_parse_junit_handles_single_testsuite_root(tmp_path: Path) -> None:
    # Single <testsuite> root with non-numeric attributes — exercises the
    # `_parse_int` / `_parse_float` ValueError fallbacks instead of raising.
    suite = tmp_path / "single.xml"
    suite.write_text(
        '<testsuite name="solo" tests="3" failures="not-a-number" '
        'errors="0" skipped="1" time="oops">'
        "<testcase /></testsuite>",
        encoding="utf-8",
    )
    parsed = parse_junit(suite)
    assert parsed.suite_name == "solo"
    assert parsed.total == 3
    assert parsed.failures == 0  # malformed attribute coerced to default
    assert parsed.skipped == 1
    assert parsed.time_seconds == 0.0  # malformed float coerced to default


def test_parse_junit_handles_legacy_skip_attribute(tmp_path: Path) -> None:
    # Legacy reporters use `skip` instead of `skipped`.
    suite = tmp_path / "legacy.xml"
    suite.write_text(
        '<testsuites><testsuite name="legacy" tests="2" skip="1"></testsuite></testsuites>',
        encoding="utf-8",
    )
    parsed = parse_junit(suite)
    assert parsed.total == 2
    assert parsed.skipped == 1
