"""Unit tests for the LocalArtifactCollector auto-detection logic.

The collector walks a directory and routes each file to the parser
whose ``_looks_like_*`` heuristic claims it. These tests pin the
auto-detection contract: an ``osv.json``-shaped file must be ingested
as an OSV report and surface as an ``sca_scan`` evidence, even though
its filename does not declare the source tool.
"""

from __future__ import annotations

import builtins
import os
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

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
    """All three directory inputs share the guard, not just artifacts.

    Two distinct files rather than one passed twice: identical (path, reason)
    pairs are de-duplicated, since the same input failing for the same reason
    is one fact however many flags pointed at it.
    """
    attestation = tmp_path / "stray-attestation.yaml"
    exception = tmp_path / "stray-exception.yaml"
    attestation.write_text("kind: attestation\n", encoding="utf-8")
    exception.write_text("kind: exception\n", encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), attestations_dirs=[attestation], exceptions_dirs=[exception]
    ).collect()

    assert len(report.errors) == 2
    assert all("not a directory" in e.reason for e in report.errors)
    assert {e.path for e in report.errors} == {attestation, exception}


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


def _osv_bytes() -> str:
    return (
        '{"results": [{"packages": [{"package": {"name": "lodash", '
        '"version": "4.17.20", "ecosystem": "npm"}, "vulnerabilities": '
        '[{"id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"], '
        '"severity": [{"type": "CVSS_V3", "score": "7.4"}]}]}]}]}'
    )


def _deny_scandir_for(blocked: Path) -> Any:
    """Return an ``os.scandir`` stand-in that refuses one directory.

    Permission bits are not portable enough to test this for real: `chmod 000`
    is a no-op for the owner on Windows, and a root CI runner walks straight
    through it on Linux. Denying at the syscall the walker actually calls
    reproduces the same OSError on every platform.
    """
    real_scandir = os.scandir

    def _scandir(path: Any = ".") -> Any:
        if Path(path) == blocked:
            raise PermissionError(13, "Permission denied", str(blocked))
        return real_scandir(path)

    return _scandir


def test_unreadable_subdirectory_is_reported_instead_of_silently_skipped(
    tmp_path: Path,
) -> None:
    """A directory the collector cannot descend into must surface as an error.

    ``Path.rglob`` is built on a glob selector that catches and drops the
    OSError ``os.scandir`` raises on an unreadable directory. The tree simply
    came back short: the evidence inside was absent from the bundle, the run
    reported `not_ready` citing missing critical evidence, and nothing anywhere
    said a directory had been skipped. The scanners had run — the collector
    could not read them and did not say so, which is the worst of both (a false
    negative wearing the costume of a real finding).
    """
    artifacts_dir = tmp_path / "artifacts"
    readable = artifacts_dir / "readable"
    blocked = artifacts_dir / "locked"
    readable.mkdir(parents=True)
    blocked.mkdir()
    (readable / "osv.json").write_text(_osv_bytes(), encoding="utf-8")
    (blocked / "osv.json").write_text(_osv_bytes(), encoding="utf-8")

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir])
    with mock.patch("os.scandir", _deny_scandir_for(blocked)):
        report = collector.collect()

    # The readable half is still collected — one unreadable folder does not
    # abort the run.
    assert len(report.evidence) == 1
    assert report.evidence[0].evidence_type == EvidenceType.SCA_SCAN

    assert len(report.errors) == 1
    error = report.errors[0]
    assert error.path == blocked
    assert "Could not read directory" in error.reason
    assert "Permission denied" in error.reason


def test_walk_order_is_deterministic_across_nested_directories(tmp_path: Path) -> None:
    """Nested traversal must stay sorted, or two identical trees hash differently.

    Bundle determinism (docs/limitations.md) depends on evidence order, and
    ``os.walk`` yields directory entries in whatever order the filesystem hands
    them over. Both the directory list and the file list are sorted explicitly.
    """
    artifacts_dir = tmp_path / "artifacts"
    for name in ("zeta", "alpha", "middle"):
        (artifacts_dir / name).mkdir(parents=True)
        (artifacts_dir / name / "osv.json").write_text(_osv_bytes(), encoding="utf-8")

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir])
    walked = collector._walk_tree(artifacts_dir, mock.MagicMock(errors=[]))

    assert [p.parent.name for p in walked] == ["alpha", "middle", "zeta"]


def test_the_same_artifact_supplied_twice_yields_one_evidence_record(
    tmp_path: Path,
) -> None:
    """One artifact at two paths is one piece of evidence, not two.

    ``evidence_id`` is a digest of the artifact's content hash plus its tool
    and release context, so identical bytes at two paths produce the *same*
    id. Two CI jobs each uploading the scanner's SARIF into their own folder
    is enough to trigger it. The bundle then carried two records under one id
    and ``evidence_refs`` no longer identified a single record — in a tool
    whose product is the audit trail. A consumer writing the obvious
    ``{e.evidence_id: e for e in bundle.evidence}`` silently kept the last.
    """
    artifacts_dir = tmp_path / "artifacts"
    for job in ("job-a", "job-b"):
        (artifacts_dir / job).mkdir(parents=True)
        (artifacts_dir / job / "semgrep.sarif").write_text(_sarif_bytes(), encoding="utf-8")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    assert len(report.evidence) == 1
    assert len({e.evidence_id for e in report.evidence}) == 1
    # The surviving record is the first in walk order, so the result is
    # deterministic rather than dependent on filesystem iteration.
    assert report.evidence[0].raw is not None
    assert "job-a" in str(report.evidence[0].raw.artifact_path)
    # A duplicate supply is not a failure; nothing is reported as an error.
    assert report.errors == []


def test_genuinely_different_records_sharing_an_id_are_reported_not_dropped(
    tmp_path: Path,
) -> None:
    """A real id collision must surface: silently dropping it would lose evidence.

    De-duplication is only safe while the two records describe the same thing.
    If they differ in substance the shared id is a defect in id derivation, and
    discarding one would delete real evidence — the exact failure this tool
    exists to prevent. Both are kept so the bundle model rejects them loudly.
    """
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "a.sarif").write_text(_sarif_bytes(), encoding="utf-8")
    (artifacts_dir / "b.sarif").write_text(_sarif_bytes(), encoding="utf-8")

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir])
    original = collector._ingest_artifact

    def _ingest_and_diverge(file_path: Path, report: Any) -> None:
        original(file_path, report)
        if file_path.name == "b.sarif" and report.evidence:
            report.evidence[-1] = report.evidence[-1].model_copy(
                update={"producer": "a-different-tool"}
            )

    with mock.patch.object(collector, "_ingest_artifact", _ingest_and_diverge):
        report = collector.collect()

    assert len(report.evidence) == 2
    assert len(report.errors) == 1
    assert "was derived for two different records" in report.errors[0].reason


def test_dedup_ignores_exactly_the_fields_the_structural_hash_calls_volatile() -> None:
    """Keep the two volatile-field lists in step without importing upwards.

    `collectors` sits below `application` in the layering, so the collector
    restates the volatile evidence fields instead of importing them. Restating
    invites drift: a field added to the structural-hash normaliser but not
    here would make two reads of one artifact look like different evidence and
    turn a duplicate supply back into a reported id collision.
    """
    from evidence_collector.application.integrity import VOLATILE_EVIDENCE
    from evidence_collector.collectors.local import _VOLATILE_EVIDENCE_FIELDS

    assert _VOLATILE_EVIDENCE_FIELDS == VOLATILE_EVIDENCE


_WAIVER = """exception_id: EXC-2026-DEMO-001
control_id: SSDF-PW.1
approver: appsec-lead@example.com
approved_at: "2026-01-01T00:00:00Z"
expires_at: "2036-01-01T00:00:00Z"
justification: No new trust boundary; follow-up scheduled for next quarter.
"""


def test_the_same_waiver_supplied_twice_yields_one_exception(tmp_path: Path) -> None:
    """`--exceptions-dir` is repeatable, and dedup was only done for evidence.

    The same waiver reaching a run through two directories produced an ACCEPTED
    bundle carrying two `EvidenceException` records under one `exception_id`,
    with `exception_refs: ['EXC-1', 'EXC-1']` on the control and a rationale
    naming the waiver twice. A waiver is the object that lets a control pass
    *without* evidence, so an ambiguous reference matters more here than
    anywhere else in the bundle.
    """
    for job in ("job-a", "job-b"):
        (tmp_path / job).mkdir()
        (tmp_path / job / "waiver.yaml").write_text(_WAIVER, encoding="utf-8")

    report = LocalArtifactCollector(
        _release(), exceptions_dirs=[tmp_path / "job-a", tmp_path / "job-b"]
    ).collect()

    assert len(report.exceptions) == 1
    assert report.errors == []


def test_two_different_waivers_sharing_an_id_are_reported_in_the_bundle(
    tmp_path: Path,
) -> None:
    """A duplicate waiver id must not end the run.

    Unlike `evidence_id`, which is a digest of the artifact's own content,
    `exception_id` is chosen by whoever wrote the waiver — a duplicate is one
    typo away. Keeping both records so the bundle model would reject them
    turned that typo into a dead run: exit 3, no bundle, no report, no summary,
    and a raw pydantic dump. The first one wins and the conflict is recorded
    where it survives — in `collection_errors`, and from there in the bundle
    and the report.
    """
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "waiver.yaml").write_text(_WAIVER, encoding="utf-8")
    (tmp_path / "b" / "waiver.yaml").write_text(
        _WAIVER.replace("appsec-lead@example.com", "someone-else@example.com"),
        encoding="utf-8",
    )

    report = LocalArtifactCollector(
        _release(), exceptions_dirs=[tmp_path / "a", tmp_path / "b"]
    ).collect()

    # One waiver applied, and the bundle can still be built.
    assert len(report.exceptions) == 1
    assert report.exceptions[0].approver == "appsec-lead@example.com"
    # The conflict is durable, not just a log line.
    assert len(report.errors) == 1
    assert "supplied twice with different content" in report.errors[0].reason
    assert "Only the first was applied" in report.errors[0].reason


def test_overlapping_artifact_dirs_do_not_double_report_one_failure(
    tmp_path: Path,
) -> None:
    """`_walk_once` de-duplicated files but not the errors beside them.

    `--artifacts-dir` is documented as repeatable, and passing a parent plus
    one of its own subdirectories is trivial in a CI matrix. One unreadable
    folder underneath then produced a single evidence record and *two*
    identical `collection_errors` entries. The bundle is the durable signed
    artifact, so overstating how many inputs failed is a defect in it.
    """
    artifacts = tmp_path / "artifacts"
    nested = artifacts / "nested"
    blocked = nested / "locked"
    nested.mkdir(parents=True)
    blocked.mkdir()
    (nested / "osv.json").write_text(_osv_bytes(), encoding="utf-8")

    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts, nested])
    with mock.patch("os.scandir", _deny_scandir_for(blocked)):
        report = collector.collect()

    assert len(report.evidence) == 1
    assert len(report.errors) == 1, [f"{e.path}: {e.reason}" for e in report.errors]


def test_a_fifo_is_skipped_without_being_opened(tmp_path: Path) -> None:
    """`os.walk` lists every non-directory entry, a wider set than files.

    Moving from `rglob(...) if p.is_file()` to `os.walk` dropped that filter,
    so FIFOs, sockets and device nodes reached ingestion. This is the case
    where the consequence is not noise: opening a FIFO named `*.json` blocks
    the JSON probe's `open()` until something writes to the other end, and
    nothing ever will. The run would hang rather than fail.

    A broken symlink is deliberately *not* covered here — it is reported, by
    `test_a_broken_link_is_reported_rather_than_silently_dropped`, because a
    dangling `sast.sarif` is evidence that was supplied and could not be read.
    An earlier version of this test asserted silence for that case and
    contradicted its sibling; only Linux ran it, so only CI could see it.
    """
    if not hasattr(os, "mkfifo"):
        pytest.skip("this platform has no FIFOs")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "osv.json").write_text(_osv_bytes(), encoding="utf-8")
    os.mkfifo(artifacts / "pipe.json")

    # Reaching the assertions at all is most of the point: opening the FIFO
    # would block here forever.
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert len(report.evidence) == 1
    assert report.errors == []


def test_an_unreadable_file_is_reported_not_fatal(tmp_path: Path) -> None:
    """`Path.is_file()` does not swallow EACCES, and it ran outside `onerror`.

    `os.walk`'s error hook only covers the directory scan; the regular-file
    filter added after it sits outside. `is_file()` swallows only
    ENOENT/ENOTDIR/EBADF/ELOOP, so EACCES, EPERM, EIO and Windows'
    ERROR_ACCESS_DENIED propagated — an unreadable *file* aborted the whole
    collection with a bare PermissionError, took every other artifact with it,
    and leaked the absolute path in the crash text past the `--artifact-root`
    redaction.
    """
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "osv.json").write_text(_osv_bytes(), encoding="utf-8")
    blocked = artifacts / "locked.sarif"
    blocked.write_text(_sarif_bytes(), encoding="utf-8")

    real_is_file = Path.is_file

    def _deny(self: Path) -> bool:
        if self == blocked:
            raise PermissionError(13, "Permission denied", str(blocked))
        return real_is_file(self)

    with mock.patch.object(Path, "is_file", _deny):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert len(report.evidence) == 1
    assert len(report.errors) == 1
    assert report.errors[0].path == blocked
    assert "Permission denied" in report.errors[0].reason


def test_a_broken_link_is_reported_rather_than_silently_dropped(tmp_path: Path) -> None:
    """A dangling `sast.sarif` is evidence that was supplied and cannot be read.

    Omitting it silently reads as "never supplied" — the false negative
    `_usable_directory`'s own docstring calls worse than an error. The
    realistic trigger is a failed CI artifact download.
    """
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "osv.json").write_text(_osv_bytes(), encoding="utf-8")
    dangling = artifacts / "sast.sarif"
    try:
        dangling.symlink_to(tmp_path / "never-downloaded.sarif")
    except (OSError, NotImplementedError):
        pytest.skip("this machine does not allow creating symlinks")

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert len(report.evidence) == 1
    assert len(report.errors) == 1
    assert "target does not exist" in report.errors[0].reason


@pytest.mark.parametrize(
    ("filename", "payload", "max_opens"),
    [
        pytest.param(
            "scan.sarif",
            '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep",'
            '"version":"1","rules":[]}},"results":[]}]}',
            2,
            id="sarif",
        ),
        pytest.param(
            "sbom.cdx.json",
            '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}',
            4,
            id="cyclonedx-json",
        ),
        pytest.param(
            "junit.xml",
            '<testsuites tests="1" failures="0" errors="0">'
            '<testsuite name="s" tests="1" failures="0" errors="0">'
            '<testcase name="t" classname="x" time="0.1"/></testsuite></testsuites>',
            2,
            id="junit-xml",
        ),
    ],
)
def test_a_recognized_artifact_is_read_a_bounded_number_of_times(
    tmp_path: Path, filename: str, payload: str, max_opens: int
) -> None:
    """The bound above covers the file nothing recognises. This covers the rest.

    `test_detection_does_not_reread_the_same_file_for_every_probe` stops at
    detection, so nothing pinned what a file costs once a parser accepts it —
    and that is the path every real artifact takes. Measured today: two opens
    for `.sarif` and `.xml` (detection, then the parser), and four for `.json`,
    which additionally pays the in-toto record probe, because an in-toto
    statement and a CycloneDX SBOM are both `.json` and cannot be told apart by
    extension, plus the integrity hash.

    Four full reads of a file that may be 25 MB is the reason to hold the line
    here rather than let it drift up one reader at a time. The peek memo
    already holds the parsed document, so a fifth reader is nearly always a
    missed reuse.

    Counts `builtins.open` as well as `Path.open`: the parsers open through the
    builtin, so patching only `Path.open` — as the detection test above does —
    sees a smaller number than the file actually pays.
    """
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / filename).write_text(payload, encoding="utf-8")

    opens = 0
    real_builtin_open = builtins.open
    real_path_open = Path.open

    def counting_builtin(file: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal opens
        try:
            if Path(file).name == filename:
                opens += 1
        except TypeError:  # a file descriptor, not a path
            pass
        return real_builtin_open(file, *args, **kwargs)

    def counting_path(self: Path, *args: Any, **kwargs: Any) -> Any:
        nonlocal opens
        if self.name == filename:
            opens += 1
        return real_path_open(self, *args, **kwargs)

    with (
        mock.patch.object(builtins, "open", counting_builtin),
        mock.patch.object(Path, "open", counting_path),
    ):
        report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts_dir]).collect()

    assert len(report.evidence) == 1, (
        "the artifact must be recognised for this bound to mean anything"
    )
    assert opens <= max_opens, f"{filename} was opened {opens} times, budget is {max_opens}"
