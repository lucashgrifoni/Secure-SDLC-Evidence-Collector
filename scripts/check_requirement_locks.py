"""Check that every hash lock in .github/requirements is what uv would compile.

Each ``.txt`` lock records the ``uv pip compile`` command that produced it.
This script copies the directory to a scratch folder, reruns each recorded
command there (uv keeps the pins already in the output file), and fails when
the result differs from the committed lock. A lock edited by hand, or
recompiled without ``--universal`` (dropping platform markers such as
``colorama ; sys_platform == 'win32'``), shows up as a difference.

With ``--refresh`` it rewrites the locks in place instead: each recorded command
runs with ``--upgrade`` and ``--exclude-newer`` set to seven days ago, so a
release younger than a week is not picked up. This replaces Dependabot's pip
updates for this directory, which recompiled without ``--universal``.

Usage: python scripts/check_requirement_locks.py [--refresh] [requirements-dir]
"""

from __future__ import annotations

import difflib
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

# The same delay the Dependabot cooldown applies to the other ecosystems.
COOLDOWN = timedelta(days=7)

_PREFIX = "#    uv pip compile "

Runner = Callable[[Sequence[str], Path], None]


def _recorded_command(lock: Path) -> list[str]:
    for line in lock.read_text(encoding="utf-8").splitlines()[:5]:
        if line.startswith(_PREFIX):
            return ["uv", "pip", "compile", *shlex.split(line.removeprefix(_PREFIX))]
    raise ValueError(f"{lock.name}: no recorded 'uv pip compile' command in the header")


def _run(command: Sequence[str], cwd: Path) -> None:
    # No shell; always `uv pip compile` with arguments from a committed lock header.
    subprocess.run([*command, "--quiet", "--no-progress"], cwd=cwd, check=True)  # noqa: S603


def stale_locks(directory: Path, run: Runner = _run) -> list[str]:
    """Return a unified diff for each lock that uv would compile differently."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch) / "requirements"
        shutil.copytree(directory, work)
        for lock in sorted(directory.glob("*.txt")):
            run(_recorded_command(lock), work)
            expected = (work / lock.name).read_text(encoding="utf-8").splitlines(keepends=True)
            actual = lock.read_text(encoding="utf-8").splitlines(keepends=True)
            if expected != actual:
                problems.append(
                    "".join(
                        difflib.unified_diff(
                            actual, expected, f"{lock.name} (committed)", f"{lock.name} (uv)"
                        )
                    )
                )
    return problems


def _without_cutoff(command: Sequence[str]) -> list[str]:
    """Drop the --exclude-newer that uv recorded from the previous refresh."""
    kept: list[str] = []
    skip_value = False
    for arg in command:
        if skip_value:
            skip_value = False
        elif arg == "--exclude-newer":
            skip_value = True
        elif not arg.startswith("--exclude-newer="):
            kept.append(arg)
    return kept


def refresh_locks(directory: Path, now: datetime, run: Runner = _run) -> list[str]:
    """Recompile every lock in place to the newest versions older than the cooldown."""
    cutoff = (now - COOLDOWN).strftime("%Y-%m-%dT00:00:00Z")
    refreshed: list[str] = []
    for lock in sorted(directory.glob("*.txt")):
        command = _without_cutoff(_recorded_command(lock))
        run([*command, "--upgrade", "--exclude-newer", cutoff], directory)
        refreshed.append(lock.name)
    return refreshed


def main(argv: Sequence[str]) -> int:
    args = list(argv[1:])
    refresh = "--refresh" in args
    if refresh:
        args.remove("--refresh")
    directory = Path(args[0]) if args else Path(".github/requirements")
    if refresh:
        names = refresh_locks(directory, datetime.now(UTC))
        print(f"Refreshed {len(names)} lock(s): {', '.join(names)}. Review the diff and run CI.")
        return 0
    problems = stale_locks(directory)
    for diff in problems:
        print(diff)
    if problems:
        print(
            f"{len(problems)} lock(s) differ from what their recorded uv command produces. "
            "Regenerate them with the command in each file's header."
        )
        return 1
    print("All requirement locks match their recorded uv command.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
