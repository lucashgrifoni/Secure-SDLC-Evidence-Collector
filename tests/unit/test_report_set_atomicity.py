"""The report set must never be observed half-updated.

`bundle.json`, `report.md` and `summary.html` are three renderings of one
verdict. They used to be rendered and written one after another with
`Path.write_text`, so any failure between them — a template error, a full
disk, Ctrl-C, a CI step timeout — left this run's `bundle.json` beside the
*previous* run's `report.md`. Nothing in those files records which run wrote
them, so the human reading the Markdown reads last release's verdict under
this release's name, and a stale `ready` is the worst value that field can
hold.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters import export_report_set
from evidence_collector.exporters._atomic import write_all_or_nothing, write_atomic

_REPORT_FILES = ("bundle.json", "report.md", "summary.html")


def _bundle(release_id: str, status: ReleaseStatus) -> EvidenceBundle:
    release = ReleaseContext(release_id=release_id, commit_sha="abcdef1234567890")
    return EvidenceBundle(
        bundle_id=f"bundle-{release_id}",
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=release,
        evidence=[
            NormalizedEvidence(
                evidence_id="ev-1",
                evidence_type=EvidenceType.SBOM,
                source=EvidenceSource(name="cyclonedx", kind="sbom"),
                producer="cyclonedx",
                subject_type=SubjectType.ARTIFACT,
                subject_ref=f"payments-api:{release_id}",
                status=EvidenceStatus.GENERATED,
                confidence=ConfidenceLevel.HIGH,
                release_id=release.release_id,
                commit_sha=release.commit_sha,
            )
        ],
        control_evaluations=[],
        summary=Summary(
            evidence_coverage_score=0,
            confidence_score=0,
            release_status=status,
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
        ),
    )


def test_report_set_is_written_together(tmp_path: Path) -> None:
    paths = export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)

    assert paths.json_path.exists()
    assert paths.markdown_path.exists()
    assert paths.html_path.exists()
    for name in _REPORT_FILES:
        assert "1.0.0" in (tmp_path / name).read_text(encoding="utf-8")


def test_a_failed_render_leaves_the_previous_run_untouched(tmp_path: Path) -> None:
    """A crash while producing the new report must not destroy the old one.

    The Markdown render is the realistic failure — it is the only one of the
    three that runs arbitrary template logic over untrusted values. Rendering
    now happens entirely before anything is written, so this case cannot leave
    a fresh `bundle.json` next to a stale `report.md`.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    before = {name: (tmp_path / name).read_text(encoding="utf-8") for name in _REPORT_FILES}

    with (
        mock.patch(
            "evidence_collector.exporters.report_set.bundle_to_markdown",
            side_effect=RuntimeError("template blew up"),
        ),
        pytest.raises(RuntimeError),
    ):
        export_report_set(_bundle("9.9.9", ReleaseStatus.NOT_READY), tmp_path)

    for name in _REPORT_FILES:
        assert (tmp_path / name).read_text(encoding="utf-8") == before[name]
    assert "9.9.9" not in before["bundle.json"]


def test_a_failed_write_leaves_the_previous_run_untouched(tmp_path: Path) -> None:
    """Disk full on the second file must not half-update the set.

    Every payload is staged to disk before any of them is moved into place, so
    an OSError partway through the set is hit while all three previous outputs
    are still intact and still agree with each other.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    before = {name: (tmp_path / name).read_text(encoding="utf-8") for name in _REPORT_FILES}

    real_open = Path.open
    calls = {"n": 0}

    def _fail_on_second_stage(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name.startswith("."):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(28, "No space left on device")
        return real_open(self, *args, **kwargs)

    with (
        mock.patch.object(Path, "open", _fail_on_second_stage),
        pytest.raises(OSError, match="No space left on device"),
    ):
        export_report_set(_bundle("9.9.9", ReleaseStatus.NOT_READY), tmp_path)

    for name in _REPORT_FILES:
        assert (tmp_path / name).read_text(encoding="utf-8") == before[name]


def test_staging_files_are_cleaned_up_after_a_failure(tmp_path: Path) -> None:
    """A failed run must not leave debris the next run has to reason about."""
    with mock.patch(
        "evidence_collector.exporters._atomic._stage",
        side_effect=[tmp_path / ".staged-a", OSError(28, "No space left on device")],
    ):
        (tmp_path / ".staged-a").write_text("staged", encoding="utf-8")
        with pytest.raises(OSError):
            write_all_or_nothing({tmp_path / "a.txt": "a", tmp_path / "b.txt": "b"})

    assert not (tmp_path / ".staged-a").exists()
    assert not (tmp_path / "a.txt").exists()
    assert list(tmp_path.iterdir()) == []


def test_write_atomic_never_leaves_a_truncated_file(tmp_path: Path) -> None:
    """`write_text` truncates before writing; `os.replace` swaps a finished file.

    A crash mid-write used to leave a half-written file where a complete one
    had been. A truncated `bundle.json` at least fails to parse — a truncated
    `report.md` just quietly ends early, and reads as a complete report.
    """
    target = tmp_path / "report.md"
    target.write_text("previous complete report", encoding="utf-8")

    with (
        mock.patch("os.replace", side_effect=OSError(13, "Permission denied")),
        pytest.raises(OSError),
    ):
        write_atomic(target, "new report")

    assert target.read_text(encoding="utf-8") == "previous complete report"
    assert [p.name for p in tmp_path.iterdir()] == ["report.md"]


def test_write_atomic_creates_missing_parent_directories(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "deeper" / "bundle.json"
    assert write_atomic(target, "{}") == target
    assert target.read_text(encoding="utf-8") == "{}"


def test_write_all_or_nothing_accepts_an_empty_set(tmp_path: Path) -> None:
    assert write_all_or_nothing({}) == []
    assert list(tmp_path.iterdir()) == []


def test_output_uses_lf_line_endings_on_every_platform(tmp_path: Path) -> None:
    """Bundles produced on Windows and Linux must be byte-identical.

    `Path.write_text` opens in text mode with `newline=None`, which translates
    every line feed to `os.linesep` — so the same bundle written on Windows
    differed from the Linux one in every line. The structural hash is over
    parsed JSON and never saw it, but the exporter's own docstring promises
    "byte-for-byte identical output", and across operating systems that was
    not true.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)

    for name in _REPORT_FILES:
        raw = (tmp_path / name).read_bytes()
        assert b"\r\n" not in raw, f"{name} was written with CRLF line endings"
