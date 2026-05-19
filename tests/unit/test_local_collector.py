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
