"""All-or-nothing writing for the report set.

`run` and `evaluate` write three files that describe one release:
`bundle.json`, `report.md` and `summary.html`. They used to be rendered and
written one after another with `Path.write_text`, which is neither atomic per
file nor coordinated across the set. Two consequences, both silent:

- An interruption between writes — Ctrl-C, a CI step timeout, the OOM killer,
  a full disk on the second file — left `bundle.json` from this run next to a
  `report.md` and `summary.html` from the *previous* one. Nothing in any of
  the three says which run it belongs to, so the human reading `report.md`
  reads last release's verdict under this release's name. A stale `ready` is
  the worst possible value for that field to hold.
- `write_text` truncates before it writes, so a crash mid-write leaves a
  half-written file where a complete one used to be. A truncated `bundle.json`
  at least fails to parse; a truncated `report.md` just quietly ends early.

Writing is therefore split in two phases. Everything is rendered into memory
first, so a template or serialisation error fails before any existing output
is touched. Then each payload is written to a temporary file in the *same*
directory (`os.replace` is only atomic within a filesystem), flushed and
fsynced, and only once all of them are safely on disk are the replaces
performed back to back.

That is as close to atomic as a multi-file commit gets without a journal: the
window where the set can be observed half-updated shrinks from "three renders
and three writes" to "three `os.replace` calls", and no individual file is
ever observed torn. A failure in the staging phase leaves every previous
output exactly as it was.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["write_all_or_nothing", "write_atomic"]


def _stage(target: Path, content: str) -> Path:
    """Write `content` next to `target` and return the temporary path."""
    temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return temp


def write_atomic(target: Path, content: str) -> Path:
    """Replace `target` with `content`, or leave it entirely untouched."""
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = _stage(target, content)
    try:
        os.replace(temp, target)
    except OSError:
        temp.unlink(missing_ok=True)
        raise
    return target


def write_all_or_nothing(payloads: dict[Path, str]) -> list[Path]:
    """Write every payload, or — as far as possible — none of them.

    Staging happens for all files before any of them is put in place, so the
    realistic failures (a full disk, a read-only output directory, a path that
    is a directory) are hit while every existing output is still intact. If
    staging fails, the temporary files are cleaned up and nothing is replaced.
    """
    if not payloads:
        return []
    staged: dict[Path, Path] = {}
    try:
        for target, content in payloads.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            staged[target] = _stage(target, content)
    except OSError:
        for temp in staged.values():
            temp.unlink(missing_ok=True)
        raise
    for target, temp in staged.items():
        os.replace(temp, target)
    return list(staged)
