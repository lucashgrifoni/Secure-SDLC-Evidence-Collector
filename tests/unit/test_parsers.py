"""Unit tests for parsers."""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.parsers import (
    parse_attestation,
    parse_junit,
    parse_osv,
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
    # T6.1 backward-compat: a CycloneDX 1.5 SBOM has neither lifecycles
    # nor inline analyses, so the new fields must be empty.
    assert parsed.lifecycle_phases == []
    assert parsed.vulnerability_analyses == []


def test_parse_sbom_cyclonedx_17_lifecycles(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom-1.7-lifecycles.cdx.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.7",
          "serialNumber": "urn:uuid:0aaaaaa0-1111-2222-3333-444444444444",
          "version": 1,
          "metadata": {
            "timestamp": "2026-05-19T08:00:00Z",
            "component": {
              "type": "application",
              "name": "payments-api",
              "version": "2026.05.19",
              "purl": "pkg:generic/acme/payments-api@2026.05.19"
            },
            "lifecycles": [
              {"phase": "build"},
              {"phase": "post-build"},
              {"name": "internal-staging-soak"}
            ]
          },
          "components": []
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_sbom(sbom_path)
    assert parsed.format == "cyclonedx"
    assert parsed.spec_version == "1.7"
    assert parsed.lifecycle_phases == ["build", "post-build", "internal-staging-soak"]
    assert parsed.vulnerability_analyses == []


def test_parse_sbom_cyclonedx_17_inline_vex(tmp_path: Path) -> None:
    sbom_path = tmp_path / "sbom-1.7-vex.cdx.json"
    sbom_path.write_text(
        """
        {
          "bomFormat": "CycloneDX",
          "specVersion": "1.7",
          "version": 1,
          "metadata": {
            "component": {
              "type": "application",
              "name": "payments-api",
              "purl": "pkg:generic/acme/payments-api@1"
            }
          },
          "components": [],
          "vulnerabilities": [
            {
              "id": "CVE-2026-0001",
              "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "response": ["will_not_fix"],
                "detail": "Vulnerable function never called from any entrypoint."
              }
            },
            {
              "id": "CVE-2026-0002",
              "analysis": {
                "state": "exploitable",
                "detail": "Triggered by anonymous POST."
              }
            },
            {
              "id": "GHSA-xxxx-yyyy-zzzz",
              "analysis": {"state": "in_triage"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_sbom(sbom_path)
    # GHSA-only entry without a CVE id must be skipped.
    assert len(parsed.vulnerability_analyses) == 2
    by_cve = {a.cve_id: a for a in parsed.vulnerability_analyses}
    assert by_cve["CVE-2026-0001"].state == "not_affected"
    assert by_cve["CVE-2026-0001"].justification == "code_not_reachable"
    assert by_cve["CVE-2026-0001"].responses == ["will_not_fix"]
    assert by_cve["CVE-2026-0002"].state == "exploitable"
    assert by_cve["CVE-2026-0002"].justification is None


def test_parse_osv_scanner_envelope(tmp_path: Path) -> None:
    osv_path = tmp_path / "osv-scanner.json"
    osv_path.write_text(
        """
        {
          "results": [
            {
              "source": {"path": "package-lock.json", "type": "lockfile"},
              "packages": [
                {
                  "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                  "vulnerabilities": [
                    {
                      "id": "GHSA-p6mc-m468-83gw",
                      "aliases": ["CVE-2020-8203"],
                      "severity": [{"type": "CVSS_V3", "score": "7.4"}]
                    }
                  ],
                  "groups": [{"ids": ["GHSA-p6mc-m468-83gw"], "max_severity": "7.4"}]
                },
                {
                  "package": {"name": "django", "version": "3.0", "ecosystem": "PyPI"},
                  "vulnerabilities": [
                    {
                      "id": "PYSEC-2020-3",
                      "aliases": ["CVE-2020-9402"],
                      "severity": [{"type": "CVSS_V3", "score": "9.1"}]
                    }
                  ]
                }
              ]
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_osv(osv_path)
    assert parsed.tool_name == "osv-scanner"
    assert parsed.total_findings == 2
    assert parsed.findings_count["high"] == 1
    assert parsed.findings_count["critical"] == 1
    assert parsed.cve_ids == ["CVE-2020-8203", "CVE-2020-9402"]
    assert parsed.ecosystems == ["npm", "PyPI"]
    assert parsed.package_count == 2


def test_parse_osv_single_record(tmp_path: Path) -> None:
    osv_path = tmp_path / "ghsa.json"
    osv_path.write_text(
        """
        {
          "id": "GHSA-xxxx-yyyy-zzzz",
          "aliases": ["CVE-2026-1234"],
          "summary": "Example.",
          "affected": [
            {"package": {"name": "foo", "ecosystem": "Go"}}
          ],
          "severity": [{"type": "CVSS_V3", "score": "3.7"}]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_osv(osv_path)
    assert parsed.tool_name == "osv"
    assert parsed.total_findings == 1
    assert parsed.findings_count["low"] == 1
    assert parsed.cve_ids == ["CVE-2026-1234"]
    assert parsed.ecosystems == ["Go"]


def test_parse_osv_rejects_unknown_shape(tmp_path: Path) -> None:
    bad_path = tmp_path / "not-osv.json"
    bad_path.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(ParseError):
        parse_osv(bad_path)


def test_parse_osv_defaults_to_medium_when_severity_missing(tmp_path: Path) -> None:
    osv_path = tmp_path / "no-severity.json"
    osv_path.write_text(
        """
        {
          "results": [
            {
              "packages": [
                {
                  "package": {"name": "leftpad", "version": "1.0.0", "ecosystem": "npm"},
                  "vulnerabilities": [{"id": "GHSA-no-severity"}]
                }
              ]
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    parsed = parse_osv(osv_path)
    assert parsed.findings_count["medium"] == 1


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
