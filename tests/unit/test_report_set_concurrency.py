"""Competing processes must not interleave a release report set."""

from __future__ import annotations

import multiprocessing
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.exporters._atomic import write_all_or_nothing, write_atomic


def _paused_writer(directory: str, started: Any, resume: Any) -> None:
    from evidence_collector.exporters import _atomic

    stage = _atomic._stage
    paused = False

    def pause_once(target: Path, content: str) -> Path:
        nonlocal paused
        staged = stage(target, content)
        if not paused:
            paused = True
            started.set()
            if not resume.wait(15):
                raise TimeoutError("test writer was not resumed")
        return staged

    _atomic._stage = pause_once
    root = Path(directory)
    _atomic.write_all_or_nothing(
        {root / name: "first" for name in ("bundle.json", "report.md", "summary.html")}
    )


@pytest.mark.parametrize("single_file", [False, True])
def test_a_competing_writer_fails_before_changing_a_report(
    tmp_path: Path, single_file: bool
) -> None:
    context = multiprocessing.get_context("spawn")
    started, resume = context.Event(), context.Event()
    writer = context.Process(target=_paused_writer, args=(str(tmp_path), started, resume))
    writer.start()
    try:
        assert started.wait(10), "first writer did not reach the coordinated write"
        with pytest.raises(OSError, match="writer"):
            if single_file:
                write_atomic(tmp_path / "bundle.json", "second")
            else:
                write_all_or_nothing(
                    {
                        tmp_path / name: "second"
                        for name in ("bundle.json", "report.md", "summary.html")
                    }
                )
        # A different output directory has no reason to conflict.
        write_atomic(tmp_path / "other" / "bundle.json", "independent")
    finally:
        resume.set()
        writer.join(10)
        if writer.is_alive():
            writer.terminate()
            writer.join(5)
    assert writer.exitcode == 0
    assert all(
        (tmp_path / name).read_text(encoding="utf-8") == "first"
        for name in ("bundle.json", "report.md", "summary.html")
    )
    write_all_or_nothing(
        {tmp_path / name: "next" for name in ("bundle.json", "report.md", "summary.html")}
    )
    assert all(
        (tmp_path / name).read_text(encoding="utf-8") == "next"
        for name in ("bundle.json", "report.md", "summary.html")
    )


def _write_many(path: str, count: int) -> None:
    from evidence_collector.exporters._atomic import write_atomic

    target = Path(path)
    for index in range(count):
        write_atomic(target, f"{target.name} {index}\n")


def test_writers_of_different_files_in_one_directory_do_not_conflict(tmp_path: Path) -> None:
    """`sarif`, `vex` and `run` into one --output-dir must not fail each other.

    The lock used to cover the whole directory, so two processes writing
    `gaps.sarif` and `vex.json` side by side raised EBUSY on most writes and the
    CLI exited 3 for a run that never touched the other's file.
    """
    context = multiprocessing.get_context("spawn")
    writers = [
        context.Process(target=_write_many, args=(str(tmp_path / name), 40))
        for name in ("gaps.sarif", "vex.json")
    ]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join(60)
    assert [writer.exitcode for writer in writers] == [0, 0]
    assert (tmp_path / "gaps.sarif").read_text(encoding="utf-8") == "gaps.sarif 39\n"
    assert (tmp_path / "vex.json").read_text(encoding="utf-8") == "vex.json 39\n"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["gaps.sarif", "vex.json"]


def test_a_held_report_set_does_not_block_a_different_file(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    started, resume = context.Event(), context.Event()
    writer = context.Process(target=_paused_writer, args=(str(tmp_path), started, resume))
    writer.start()
    try:
        assert started.wait(10), "first writer did not reach the coordinated write"
        write_atomic(tmp_path / "gaps.sarif", "independent")
    finally:
        resume.set()
        writer.join(10)
    assert writer.exitcode == 0
    assert (tmp_path / "gaps.sarif").read_text(encoding="utf-8") == "independent"


def _deny_lock_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, windows: bool
) -> tuple[OSError, int]:
    import errno
    import os
    import time

    from evidence_collector.exporters import _atomic

    attempts: list[object] = []

    def denied(*args: object, **_kwargs: object) -> int:
        attempts.append(args[0])
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(_atomic, "_WINDOWS", windows, raising=False)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    with monkeypatch.context() as patched:
        patched.setattr(os, "open", denied)
        with pytest.raises(OSError) as caught:
            write_atomic(tmp_path / "bundle.json", "x")
    return caught.value, len(attempts)


def test_windows_lock_contention_reports_the_busy_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A delete-pending lock on Windows raises PermissionError, not EEXIST."""
    import errno

    error, attempts = _deny_lock_creation(monkeypatch, tmp_path, windows=True)
    assert error.errno == errno.EBUSY
    assert "Another writer" in str(error)
    assert attempts > 1, "a delete-pending lock clears quickly, so retry first"


def test_a_permission_error_elsewhere_is_not_reported_as_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    error, attempts = _deny_lock_creation(monkeypatch, tmp_path, windows=False)
    assert isinstance(error, PermissionError)
    assert attempts == 1


def test_the_busy_error_names_the_lock_and_says_to_delete_only_it(tmp_path: Path) -> None:
    lock = tmp_path / ".bundle.json.lock"
    lock.write_text("pid=1\n", encoding="ascii")
    with pytest.raises(OSError) as caught:
        write_atomic(tmp_path / "bundle.json", "x")
    message = str(caught.value)
    assert str(lock) in message
    assert "delete only" in message
    assert "never" in message
    assert not (tmp_path / "bundle.json").exists()
    assert lock.exists(), "a lock this writer did not create must not be removed"


def test_a_failed_report_set_releases_its_locks(tmp_path: Path) -> None:
    (tmp_path / "report.md").mkdir()
    with pytest.raises(IsADirectoryError):
        write_all_or_nothing(
            {tmp_path / name: "x" for name in ("bundle.json", "report.md", "summary.html")}
        )
    assert sorted(path.name for path in tmp_path.iterdir()) == ["report.md"]


def test_a_successful_report_set_leaves_no_lock_or_scratch_file(tmp_path: Path) -> None:
    names = ("bundle.json", "report.md", "summary.html")
    for name in names:
        (tmp_path / name).write_text("old", encoding="utf-8")
    write_all_or_nothing({tmp_path / name: "new" for name in names})
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(names)


def test_a_non_ascii_hostname_does_not_break_the_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows allows accented computer names and returns them as Unicode.
    from evidence_collector.exporters import _atomic

    monkeypatch.setattr("socket.gethostname", lambda: "LUCÍA-PC")
    seen: list[str] = []
    stage = _atomic._stage

    def record_lock(target: Path, content: str) -> Path:
        seen.append((target.parent / f".{target.name}.lock").read_text(encoding="utf-8"))
        return stage(target, content)

    monkeypatch.setattr(_atomic, "_stage", record_lock)
    write_atomic(tmp_path / "bundle.json", "x")
    assert (tmp_path / "bundle.json").read_text(encoding="utf-8") == "x"
    assert seen and "host=LUCÍA-PC\n" in seen[0]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bundle.json"]
