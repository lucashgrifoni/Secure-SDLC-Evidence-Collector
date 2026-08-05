"""Unit tests for the LocalArtifactCollector auto-detection logic.

The collector walks a directory and routes each file to the parser
whose ``_looks_like_*`` heuristic claims it. These tests pin the
auto-detection contract: an ``osv.json``-shaped file must be ingested
as an OSV report and surface as an ``sca_scan`` evidence, even though
its filename does not declare the source tool.
"""

from __future__ import annotations

from pathlib import Path

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceType
from evidence_collector.domain.models import ReleaseContext


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.05.19", commit_sha="abcdef1234567890")


def test_local_collector_auto_detects_osv_scanner_envelope(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    osv_path = artifacts_dir / "osv.json"
    osv_path.write_text(
        """
        {
          "results": [
            {
              "packages": [
                {
                  "package": {"name": "lodash", "version": "4.17.20", "ecosystem": "npm"},
                  "vulnerabilities": [
                    {
                      "id": "GHSA-p6mc-m468-83gw",
                      "aliases": ["CVE-2020-8203"],
                      "severity": [{"type": "CVSS_V3", "score": "7.4"}]
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

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir])
    report = collector.collect()

    assert report.errors == []
    assert len(report.evidence) == 1
    evidence = report.evidence[0]
    assert evidence.evidence_type == EvidenceType.SCA_SCAN
    assert evidence.producer == "osv-scanner"
    assert evidence.metadata.get("ecosystems") == ["npm"]
    assert "CVE-2020-8203" in evidence.cve_ids


# ---------------------------------------------------------------------------
# Mis-encoded artifacts must not destroy the run (ING-01)
#
# A single file the collector cannot decode used to raise UnicodeDecodeError
# out of the detection helpers, aborting collection before any bundle was
# written — every other artifact in the directory was lost with it. The
# contrast that made this a defect rather than a design choice: the same bytes
# in a `.xml` already degraded into a collection warning.
# ---------------------------------------------------------------------------


def _sarif_bytes() -> str:
    return """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
          "results": []
        }
      ]
    }
    """


def test_undecodable_artifact_does_not_abort_the_collection(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "good.sarif").write_text(_sarif_bytes(), encoding="utf-8")
    (artifacts_dir / "bad.json").write_bytes(b'{"runs": [], "x": "\xff\xfe"}')

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    # The valid artifact survives...
    assert len(report.evidence) == 1
    assert report.evidence[0].evidence_type == EvidenceType.SAST_SCAN
    # ...and the unreadable one is reported instead of silently dropped.
    assert len(report.errors) == 1
    assert report.errors[0].path.name == "bad.json"
    assert "Invalid text encoding" in report.errors[0].reason


def test_valid_sarif_saved_as_utf16_is_reported_not_crashed(tmp_path: Path) -> None:
    """`scanner --json > report.sarif` under PowerShell 5.1 writes UTF-16."""
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "semgrep.sarif").write_bytes(_sarif_bytes().encode("utf-16"))

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    assert report.evidence == []
    assert len(report.errors) == 1
    assert "Invalid text encoding" in report.errors[0].reason


def test_unrecognized_but_readable_artifact_stays_silent(tmp_path: Path) -> None:
    """Only *undecodable* files become errors; unknown formats stay debug-level.

    Without this, every stray README or config file in an artifacts directory
    would show up as a collection warning.
    """
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "notes.json").write_text('{"hello": "world"}', encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    assert report.evidence == []
    assert report.errors == []
