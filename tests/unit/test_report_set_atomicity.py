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

import os
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
from evidence_collector.exporters import _atomic, export_report_set
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


def test_a_failure_during_the_replace_phase_rolls_the_whole_set_back(
    tmp_path: Path,
) -> None:
    """The staging phase was hardened; the replace phase had no handling at all.

    `write_all_or_nothing` ended in a bare `for target, temp: os.replace(...)`.
    Payloads are ordered bundle.json, report.md, summary.html, so a failure on
    the second replace published the NEW bundle.json beside the PREVIOUS run's
    report.md and summary.html — precisely the half-updated state this module's
    docstring claims is unreachable. On Windows that is not exotic: a read-only
    destination, another process holding the file open, or a target that exists
    as a directory all raise there.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    before = {name: (tmp_path / name).read_text(encoding="utf-8") for name in _REPORT_FILES}

    real_replace = os.replace
    calls = {"n": 0}

    def _fail_on_the_second_move_into_place(src: Any, dst: Any, **kwargs: Any) -> None:
        # Only count moves INTO place (the source is a scratch file).
        # Moves INTO place: the source is a scratch file, the destination is not.
        if "~n" in Path(str(src)).name and "~" not in Path(str(dst)).name:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(13, "Permission denied")
        real_replace(src, dst, **kwargs)

    with (
        mock.patch("os.replace", _fail_on_the_second_move_into_place),
        pytest.raises(OSError, match="Permission denied"),
    ):
        export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    for name in _REPORT_FILES:
        assert (tmp_path / name).read_text(encoding="utf-8") == before[name], (
            f"{name} was left holding the wrong run's content"
        )


def test_no_scratch_files_survive_a_replace_phase_failure(tmp_path: Path) -> None:
    """A failed run must not leave debris the next run has to reason about.

    `write_atomic` cleaned up its temp on failure; `write_all_or_nothing` did
    not, so a real CLI run left `.report.md.<pid>.tmp` and
    `.summary.html.<pid>.tmp` in the output directory permanently.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)

    real_replace = os.replace
    calls = {"n": 0}

    def _fail_on_the_second_move_into_place(src: Any, dst: Any, **kwargs: Any) -> None:
        # Moves INTO place: the source is a scratch file, the destination is not.
        if "~n" in Path(str(src)).name and "~" not in Path(str(dst)).name:
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(13, "Permission denied")
        real_replace(src, dst, **kwargs)

    with (
        mock.patch("os.replace", _fail_on_the_second_move_into_place),
        pytest.raises(OSError),
    ):
        export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    leftovers = sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("."))
    assert leftovers == [], f"scratch files left behind: {leftovers}"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(_REPORT_FILES)


def test_a_successful_write_leaves_only_the_report_set(tmp_path: Path) -> None:
    """Backups are scratch too: they must not survive a run that succeeded."""
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(_REPORT_FILES)
    for name in _REPORT_FILES:
        assert "2.0.0" in (tmp_path / name).read_text(encoding="utf-8")


def test_two_exports_from_one_process_do_not_collide(tmp_path: Path) -> None:
    """Scratch names were unique per process, not per call.

    `.{name}.{pid}.tmp` meant two `export_report_set` calls in one process
    against one output directory raced on the same scratch paths: one run
    replaced the other's staged file mid-flight, and in one observed case
    `summary.html` ended up missing entirely.
    """
    seen: list[str] = []
    real_stage = _atomic._stage

    def _record(target: Path, content: str) -> Path:
        staged = real_stage(target, content)
        seen.append(staged.name)
        return staged

    with mock.patch.object(_atomic, "_stage", _record):
        export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
        export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    assert len(seen) == len(set(seen)), f"scratch names repeated across calls: {seen}"
    for name in _REPORT_FILES:
        assert "2.0.0" in (tmp_path / name).read_text(encoding="utf-8")


def test_every_command_that_writes_a_json_artifact_uses_the_atomic_writer() -> None:
    """`enrich` rewrote bundle.json in place with `Path.write_text`.

    That is the truncating, line-ending-translating call this module exists to
    replace, applied to the one file the whole tool protects — and `--output`
    defaults to overwriting BUNDLE_PATH in place, so a crash mid-write
    destroyed the bundle. It also rewrote it with CRLF, silently undoing the LF
    invariant the exporters pin.

    The same call was in `collect`, `guac`, `oscal`, `statement` and `vex`,
    each writing a file a later command reads back.

    The source tree is located through the *imported package*, not through a
    cwd-relative string. Written the obvious way — `Path("src/evidence_collector/
    cli/commands")` — this guard globbed zero files from any other working
    directory and passed vacuously, so a tox run, an IDE runner or a packaged
    wheel silently disarmed it; run from a tree that merely happened to contain
    a `src/`, it audited that tree instead of the code under test.
    """
    import evidence_collector.cli.commands as package

    commands = Path(package.__file__).parent
    assert commands.is_dir()

    # Anything that opens a file for writing, not just `.write_text(` — the
    # first version of this guard matched that one literal, so `open(..., "w")`,
    # `write_bytes` and `json.dump(fp)` all sailed through.
    writers = (".write_text(", ".write_bytes(", "json.dump(", "open(")
    scanned = [path for path in sorted(commands.glob("*.py")) if path.name != "schema.py"]
    # Without this the guard cannot fail: an empty file list makes
    # `offenders == []` trivially true, which is exactly how it passed
    # vacuously from every working directory but one.
    assert len(scanned) > 10, f"the guard scanned only {len(scanned)} files"

    offenders = [
        f"{path.name}:{number}"
        for path in sorted(commands.glob("*.py"))
        # `schema` is the one deliberate exception: it already writes with an
        # explicit newline="\n", and its only exposure is truncation on a crash
        # mid-write. It is still a published artifact, so this is a narrow
        # carve-out rather than a claim that the file does not matter.
        if path.name != "schema.py"
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if any(writer in line for writer in writers)
    ]
    assert offenders == [], f"non-atomic writes remain: {offenders}"


def test_an_interrupt_leaves_the_previous_run_readable(tmp_path: Path) -> None:
    """Ctrl-C is the first failure this module's docstring names, and it broke it.

    Phase 2 moves every target aside before phase 3 puts any back, so an
    interrupt inside that window left the output directory with the report
    files MISSING — worse than the half-updated set the module exists to
    prevent, and worse than the `write_text` code it replaced, which always
    left three complete readable files. `except OSError` steps straight over
    KeyboardInterrupt, so nothing unwound.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    before = {name: (tmp_path / name).read_text(encoding="utf-8") for name in _REPORT_FILES}

    real_replace = os.replace
    moves = {"n": 0}

    def _interrupt_after_moving_everything_aside(src: Any, dst: Any, **kwargs: Any) -> None:
        real_replace(src, dst, **kwargs)
        # Count only the move-aside renames (target -> scratch).
        if not str(src).startswith(".") and "~o" in Path(str(dst)).name:
            moves["n"] += 1
            if moves["n"] == len(_REPORT_FILES):
                raise KeyboardInterrupt

    with (
        mock.patch("os.replace", _interrupt_after_moving_everything_aside),
        pytest.raises(KeyboardInterrupt),
    ):
        export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    for name in _REPORT_FILES:
        assert (tmp_path / name).exists(), f"{name} vanished on interrupt"
        assert (tmp_path / name).read_text(encoding="utf-8") == before[name]
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(_REPORT_FILES)


def test_a_target_that_is_a_directory_is_rejected_before_anything_moves(
    tmp_path: Path,
) -> None:
    """Otherwise phase 2 renames the user's directory away and leaves it there.

    The commit that introduced the move-aside claimed this case was handled.
    It was not: staging writes a differently named file and succeeds, so the
    failure landed in phase 2, which happily renamed the whole directory —
    contents included — to a scratch name.
    """
    export_report_set(_bundle("1.0.0", ReleaseStatus.READY), tmp_path)
    (tmp_path / "report.md").unlink()
    blocking = tmp_path / "report.md"
    blocking.mkdir()
    (blocking / "someone-elses-file.txt").write_text("keep me", encoding="utf-8")

    with pytest.raises(IsADirectoryError):
        export_report_set(_bundle("2.0.0", ReleaseStatus.NOT_READY), tmp_path)

    assert blocking.is_dir()
    assert (blocking / "someone-elses-file.txt").read_text(encoding="utf-8") == "keep me"
    # bundle.json still describes the run that actually completed.
    assert "1.0.0" in (tmp_path / "bundle.json").read_text(encoding="utf-8")


def test_the_scratch_name_does_not_lengthen_the_path_more_than_before(
    tmp_path: Path,
) -> None:
    """Windows caps a path at 260 characters without LongPathsEnabled.

    Every character the scratch name adds is length the caller can no longer
    use. A `.{name}.{kind}.{uuid4:12}.tmp` scheme cost 22 characters over the
    target and broke `run` and `enrich` at a CI path that had worked before.
    The pid scheme it replaced cost 11, so that is the budget to beat.
    """
    target = tmp_path / "bundle.json"
    overhead = len(_atomic._scratch(target, "new").name) - len(target.name)

    assert overhead <= 11, f"scratch name adds {overhead} characters to the path"


def test_write_atomic_leaves_no_scratch_when_interrupted(tmp_path: Path) -> None:
    """An interrupt between staging and the rename must not leave a copy behind.

    `write_atomic` caught only OSError, so Ctrl-C in that window left the
    staged file next to the real output. `enrich` writes `bundle.json` through
    here, so the leftover would be a full unlabelled bundle sitting beside the
    bundle — in the directory the tool publishes.
    """
    target = tmp_path / "bundle.json"
    target.write_text('{"release": "1.0.0"}', encoding="utf-8")

    with (
        mock.patch("os.replace", side_effect=KeyboardInterrupt),
        pytest.raises(KeyboardInterrupt),
    ):
        write_atomic(target, '{"release": "2.0.0"}')

    assert target.read_text(encoding="utf-8") == '{"release": "1.0.0"}'
    assert [p.name for p in tmp_path.iterdir()] == ["bundle.json"]


def test_scratch_naming_gives_up_rather_than_spinning(tmp_path: Path) -> None:
    """A filesystem that claims every candidate exists must not hang a writer."""
    with (
        mock.patch.object(Path, "exists", lambda self: True),
        pytest.raises(OSError, match="unused temporary name"),
    ):
        _atomic._scratch(tmp_path / "bundle.json", "new")


def test_no_scratch_survives_an_interrupt_inside_the_write_itself(tmp_path: Path) -> None:
    """The callers can only clean up a scratch path `_stage` has returned.

    An interrupt or a full disk part-way through the write leaves a partial
    file none of them knows about, so the previous commit's `BaseException`
    guard in `write_atomic` had nothing to unlink. `enrich` writes
    `bundle.json` through this path, so the leftover is a partial bundle in the
    published output directory.
    """
    target = tmp_path / "bundle.json"
    target.write_text('{"release": "1.0.0"}', encoding="utf-8")
    real_open = Path.open

    def _die_mid_write(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self.name.startswith("."):
            handle = real_open(self, *args, **kwargs)
            handle.write("partial")
            handle.close()
            raise KeyboardInterrupt
        return real_open(self, *args, **kwargs)

    with (
        mock.patch.object(Path, "open", _die_mid_write),
        pytest.raises(KeyboardInterrupt),
    ):
        write_atomic(target, '{"release": "2.0.0"}')

    assert target.read_text(encoding="utf-8") == '{"release": "1.0.0"}'
    assert [p.name for p in tmp_path.iterdir()] == ["bundle.json"]
