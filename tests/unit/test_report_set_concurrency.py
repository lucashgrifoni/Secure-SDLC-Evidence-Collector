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
