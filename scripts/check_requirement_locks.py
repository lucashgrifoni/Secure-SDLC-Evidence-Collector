"""Check that every hash lock in .github/requirements is what uv would compile.

Each ``.txt`` lock records the ``uv pip compile`` command that produced it.
This script copies the directory to a scratch folder, reruns each recorded
command there (uv keeps the pins already in the output file), and fails when
the result differs from the committed lock. A lock edited by hand, or
recompiled without ``--universal`` (dropping platform markers such as
``colorama ; sys_platform == 'win32'``), shows up as a difference.

Usage: python scripts/check_requirement_locks.py [requirements-dir]
"""

from __future__ import annotations

import difflib
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

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


def main(argv: Sequence[str]) -> int:
    directory = Path(argv[1]) if len(argv) > 1 else Path(".github/requirements")
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
