"""Unit tests for the LocalArtifactCollector auto-detection logic.

The collector walks a directory and routes each file to the parser
whose ``_looks_like_*`` heuristic claims it. These tests pin the
auto-detection contract: an ``osv.json``-shaped file must be ingested
as an OSV report and surface as an ``sca_scan`` evidence, even though
its filename does not declare the source tool.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest import mock

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


# ---------------------------------------------------------------------------
# A path that is not a directory must be reported, not silently ignored (EVD-01)
#
# The guard was `not directory.exists()`, which a *file* passes. `Path.rglob`
# over a file yields nothing, so the run produced zero evidence with no warning
# whatsoever — a report claiming SAST/SCA/secrets evidence is missing while the
# scanners actually ran. The realistic trigger is a shell glob:
# `--artifacts-dir artifacts/*.sarif` expands to a file.
# ---------------------------------------------------------------------------


def test_file_passed_as_artifacts_dir_is_reported(tmp_path: Path) -> None:
    artifact = tmp_path / "semgrep.sarif"
    artifact.write_text(_sarif_bytes(), encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifact]).collect()

    assert report.evidence == []
    assert len(report.errors) == 1
    assert "not a directory" in report.errors[0].reason
    assert report.errors[0].path == artifact


def test_missing_directory_is_still_reported_distinctly(tmp_path: Path) -> None:
    """The two failure modes must stay distinguishable to the reader."""
    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[tmp_path / "does-not-exist"]
    ).collect()

    assert len(report.errors) == 1
    assert report.errors[0].reason == "directory not found"


def test_file_passed_as_attestations_or_exceptions_dir_is_reported(tmp_path: Path) -> None:
    """All three directory inputs share the guard, not just artifacts."""
    stray = tmp_path / "stray.yaml"
    stray.write_text("kind: attestation\n", encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), attestations_dirs=[stray], exceptions_dirs=[stray]
    ).collect()

    assert len(report.errors) == 2
    assert all("not a directory" in e.reason for e in report.errors)


def test_oversized_artifact_is_reported_not_dropped(tmp_path: Path) -> None:
    """Enforcing the cap in detection must not turn a loud failure into silence.

    Before PERF-01 an oversized `.json` was parsed by detection, claimed by a
    parser, and rejected by `ensure_file` — noisy, but the user was told. Now
    detection skips it, so without this the file would fall through to
    "unrecognized" and disappear. It is evidence the caller supplied.
    """
    from evidence_collector.parsers._common import MAX_INPUT_BYTES

    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    big = artifacts_dir / "huge.json"
    big.write_text('{"runs": []}', encoding="utf-8")
    os.truncate(big, MAX_INPUT_BYTES + 1)

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    assert report.evidence == []
    assert len(report.errors) == 1
    assert "safety cap" in report.errors[0].reason


def test_detection_does_not_reread_the_same_file_for_every_probe(tmp_path: Path) -> None:
    """Seven detectors used to deserialize the same document seven times."""
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    target = artifacts_dir / "unrecognized.json"
    target.write_text('{"hello": "world"}', encoding="utf-8")

    opens = 0
    real_open = Path.open

    def counting_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        nonlocal opens
        if self.name == "unrecognized.json":
            opens += 1
        return real_open(self, *args, **kwargs)

    with mock.patch.object(Path, "open", counting_open):
        LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    # Three distinct readers remain, each reading once: the memoized JSON peek
    # shared by seven detectors, the memoized in-toto record reader shared by
    # the provenance and release-attestation detectors (it parses JSONL, so it
    # cannot reuse the single-document peek), and the 8 KB encoding probe on
    # the fallthrough. Before the memos, the peek alone accounted for seven
    # full deserializations. Adding an in-toto predicate must reuse the record
    # memo rather than raise this bound.
    assert opens <= 3, f"detection opened the file {opens} times"


def test_malformed_json_artifact_is_reported_not_dropped(tmp_path: Path) -> None:
    """A .json file that no detector claims and that is not valid JSON must be
    reported. It used to vanish while byte-identical content named .sarif
    produced a warning — purely because the SARIF branch parses eagerly.
    Truncated scanner output is exactly how this happens in a pipeline, and a
    report that silently understates coverage is worse than one that errors.
    """
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "broken.json").write_text('{ "runs": [ truncated', encoding="utf-8")
    (artifacts_dir / "broken.sarif").write_text('{ "runs": [ truncated', encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    reported = {error.path.name for error in report.errors}
    assert reported == {"broken.json", "broken.sarif"}
    assert not report.evidence


def test_empty_json_artifact_is_reported(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "empty.json").write_text("", encoding="utf-8")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()
    assert [e.path.name for e in report.errors] == ["empty.json"]
    assert "empty" in report.errors[0].reason.lower()


def test_partially_written_jsonl_with_one_good_line_is_not_reported(tmp_path: Path) -> None:
    # A JSONL is valid when any line parses as an object — that is the shape
    # the in-toto detectors accept — so a truncated tail must not be flagged
    # as a broken file when usable records were read.
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "partial.jsonl").write_text(
        '{"hello": "world"}\n{"truncated": ', encoding="utf-8"
    )
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()
    assert not report.errors


def test_unrecognized_but_valid_json_is_still_ignored_quietly(tmp_path: Path) -> None:
    # The fix must not turn "format we do not model" into an error.
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "unknown.json").write_text('{"hello": "world"}', encoding="utf-8")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()
    assert not report.errors
    assert not report.evidence


# ---------------------------------------------------------------------------
# Overlapping directories must not double-ingest
#
# `--artifacts-dir` is repeatable, and passing a parent plus one of its own
# subdirectories made rglob yield the nested files under both roots. Every one
# was ingested twice, producing duplicate evidence with COLLIDING evidence_id
# values — the id is derived from the artifact hash and context, so the same
# file always yields the same id — and the coverage and confidence scores were
# computed over the inflated set.
# ---------------------------------------------------------------------------


def test_overlapping_artifacts_dirs_ingest_each_file_once(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    nested = artifacts_dir / "scanners"
    nested.mkdir(parents=True)
    (nested / "semgrep.sarif").write_text(_sarif_bytes(), encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir, nested]).collect()

    assert len(report.evidence) == 1
    assert report.inspected_files == 1
    assert len({e.evidence_id for e in report.evidence}) == 1


def test_the_same_directory_passed_twice_ingests_once(tmp_path: Path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "semgrep.sarif").write_text(_sarif_bytes(), encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), artifacts_dirs=[artifacts_dir, artifacts_dir]
    ).collect()

    assert len(report.evidence) == 1


def test_distinct_directories_still_both_ingested(tmp_path: Path) -> None:
    # De-duplication must not swallow genuinely separate inputs.
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "semgrep.sarif").write_text(_sarif_bytes(), encoding="utf-8")
    (second / "gitleaks.sarif").write_text(
        _sarif_bytes().replace("semgrep", "gitleaks"), encoding="utf-8"
    )

    report = LocalArtifactCollector(_release(), artifacts_dirs=[first, second]).collect()

    assert len(report.evidence) == 2
    assert len({e.evidence_id for e in report.evidence}) == 2
