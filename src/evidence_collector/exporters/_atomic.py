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

import errno
import logging
import os
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["write_all_or_nothing", "write_atomic"]


def _scratch(target: Path, kind: str) -> Path:
    """Return an unused scratch path beside `target`.

    Two constraints pull against each other here.

    Unique per *call*, not per process: the name was once `.{name}.{pid}.tmp`,
    so two exports to one directory from a single process — a library caller,
    a loop over releases — raced on identical paths and one replaced the
    other's staged file mid-flight, in one case leaving `summary.html` missing
    entirely.

    And short. Windows without `LongPathsEnabled` caps a path at 260
    characters, so every character the scratch name adds is a path length the
    caller can no longer use. A `.{name}.{kind}.{uuid4:12}.tmp` scheme cost
    22 characters over the target and broke `run` and `enrich` at a plausible
    CI path that had worked before — a regression paid for by uniqueness we
    did not need that much of. One marker character plus six hex digits is
    seven over the target, less than the pid scheme it replaced, and the
    while-loop below removes the birthday risk that shortening introduces.
    """
    marker = kind[0]
    while True:
        candidate = target.with_name(f".{target.name}~{marker}{uuid.uuid4().hex[:6]}")
        if not candidate.exists():
            return candidate


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
    """Remove a scratch file, saying so out loud if it cannot be removed.

    This used to log at debug, which meant a backup that inherited whatever
    made the original un-removable stayed in the output directory forever,
    after an exit-0 run, with no warning anywhere. For an evidence tool that
    debris is not litter: each leftover is an unlabelled copy of a previous
    release's full bundle sitting beside the current one.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:  # pragma: no cover - depends on filesystem state
        logger.warning(
            "Could not remove the temporary file %s (%s). It holds a copy of a "
            "previous run's output and should be deleted by hand.",
            path,
            exc.strerror or exc,
        )


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

    # A target that already exists as a *directory* has to be rejected before
    # anything moves. Otherwise phase 2 happily renames the whole directory —
    # with the user's files inside it — to a scratch name and leaves it there.
    for target in payloads:
        if target.is_dir():
            raise IsADirectoryError(errno.EISDIR, "Output path exists as a directory", str(target))

    staged: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for target, content in payloads.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            staged[target] = _stage(target, content)
        for target in staged:
            if target.exists():
                # Record where the file is going *before* moving it. Recording
                # afterwards leaves a window — one interrupt wide — in which the
                # target has already been renamed away and the unwind does not
                # know the backup exists, so it never puts it back. The restore
                # loop skips a backup that was never created, which is what an
                # interrupt in the other half of this window leaves behind.
                backup = _scratch(target, "old")
                backups[target] = backup
                os.replace(target, backup)
        for target, temp in staged.items():
            os.replace(temp, target)
            replaced.append(target)
    # BaseException, not OSError, and the reason is the failure this module
    # names first. Phase 2 moves every target aside before phase 3 puts any
    # back, so an interrupt inside that window leaves the output directory with
    # the report files MISSING — worse than the half-updated set this module
    # exists to prevent, and worse than the code it replaced, which always left
    # three complete files. KeyboardInterrupt and SystemExit are not OSErrors,
    # so `except OSError` stepped straight over Ctrl-C and the CI step timeout.
    except BaseException:
        for target in reversed(replaced):
            _unlink_quietly(target)
        for target, backup in backups.items():
            if not backup.exists():
                # The move-aside was recorded but never happened, so the target
                # is still where it belongs.
                continue
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
