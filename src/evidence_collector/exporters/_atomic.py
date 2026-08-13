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

import logging
import os
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["write_all_or_nothing", "write_atomic"]


def _scratch(target: Path, kind: str) -> Path:
    """Return an unused scratch path beside `target`.

    The name used to be `.{name}.{pid}.tmp`, which is unique per *process*,
    not per call. Two exports to one directory from a single process — a
    library caller, a test, a loop over releases — collided: one run replaced
    the other's staged file mid-flight and the set came out inconsistent, in
    one case with `summary.html` missing entirely. `uuid4` costs nothing here
    and removes the sharp edge.
    """
    return target.with_name(f".{target.name}.{kind}.{uuid.uuid4().hex[:12]}.tmp")


def _stage(target: Path, content: str) -> Path:
    """Write `content` next to `target` and return the temporary path."""
    temp = _scratch(target, "new")
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


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:  # pragma: no cover - best-effort cleanup
        logger.debug("Could not remove temporary file %s", path)


def write_all_or_nothing(payloads: dict[Path, str]) -> list[Path]:
    """Write every payload, or leave every existing file exactly as it was.

    Three phases, so there is no point at which some targets hold new content
    and others hold old:

    1. stage every payload to its own scratch file and fsync it,
    2. move each existing target aside to a backup scratch file,
    3. move each staged file into place.

    A failure anywhere unwinds: backups are moved back, scratch files are
    removed, and the original exception propagates. Previously phase 3 was a
    bare loop with no handling at all, so a failure on the second of three
    replaces published the new `bundle.json` beside the previous run's
    `report.md` and `summary.html` — the exact half-updated state this module
    exists to prevent — and left the remaining scratch files behind.

    Phase 2 is also what makes a locked destination safe. On Windows
    `os.replace` fails when another process holds the target open (a browser
    previewing `summary.html`, a publish step, an AV scanner), and so does the
    move-aside, so the run fails with every previous output still intact and
    consistent instead of half-updating. `Path.write_text` used to succeed
    there, so this is a real behaviour change: a locked output file now fails
    the run. That is the honest trade — the alternative is a report set whose
    three files disagree about which release they describe, with nothing in
    them saying so.
    """
    if not payloads:
        return []

    staged: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for target, content in payloads.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            staged[target] = _stage(target, content)
        for target in staged:
            if target.exists():
                backup = _scratch(target, "old")
                os.replace(target, backup)
                backups[target] = backup
        for target, temp in staged.items():
            os.replace(temp, target)
            replaced.append(target)
    except OSError:
        for target in reversed(replaced):
            _unlink_quietly(target)
        for target, backup in backups.items():
            try:
                os.replace(backup, target)
            except OSError:  # pragma: no cover - the filesystem is failing hard
                logger.error(
                    "Could not restore %s from %s after a failed write; the "
                    "previous content is still in the backup file.",
                    target,
                    backup,
                )
        for temp in staged.values():
            _unlink_quietly(temp)
        raise

    for backup in backups.values():
        _unlink_quietly(backup)
    return list(staged)
