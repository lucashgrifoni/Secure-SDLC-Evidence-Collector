#!/usr/bin/env python3
"""Scrub author-specific absolute paths from recorded lab artifacts.

Scanners like Trivy and Syft embed the absolute path of the scanned
target in their SARIF / SBOM output. For public lab fixtures we rewrite
those paths into a stable `./<lab-name>/` prefix so the bundled
examples do not leak the author's filesystem layout.

Usage: python scripts/scrub_lab_artifacts.py
"""

from __future__ import annotations

import re
from pathlib import Path

COLLECTOR_ROOT = Path(__file__).resolve().parent.parent
LABS_ROOT = COLLECTOR_ROOT / "examples" / "labs"
SELF = COLLECTOR_ROOT / "examples" / "self_release" / "artifacts"
SAMPLE = COLLECTOR_ROOT / "examples" / "sample_release" / "artifacts"

# Patterns that indicate a local absolute path. We match both forward-
# and back-slash variants because scanners emit either depending on OS.
_ABS_WINDOWS = re.compile(r"[A-Za-z]:[\\/][^\"',;\s]*", re.IGNORECASE)
_HOME_POSIX = re.compile(r"/(?:home|Users)/[^/\"',;\s]+/[^\"',;\s]*")


def _scrub_text(raw: str, lab_hint: str) -> str:
    """Replace absolute paths with a stable ./<lab>/ prefix."""

    def _repl_win(match: re.Match[str]) -> str:
        path = match.group(0).replace("\\", "/")
        # Keep the tail after the lab name, if we can find it.
        if f"/{lab_hint}/" in path:
            tail = path.split(f"/{lab_hint}/", 1)[1]
            return f"./{lab_hint}/{tail}"
        if path.endswith(f"/{lab_hint}"):
            return f"./{lab_hint}"
        return f"./{lab_hint}"

    def _repl_posix(match: re.Match[str]) -> str:
        path = match.group(0)
        if f"/{lab_hint}/" in path:
            tail = path.split(f"/{lab_hint}/", 1)[1]
            return f"./{lab_hint}/{tail}"
        if path.endswith(f"/{lab_hint}"):
            return f"./{lab_hint}"
        return f"./{lab_hint}"

    raw = _ABS_WINDOWS.sub(_repl_win, raw)
    raw = _HOME_POSIX.sub(_repl_posix, raw)
    return raw


def _scrub_file(path: Path, lab_hint: str) -> bool:
    before = path.read_text(encoding="utf-8")
    after = _scrub_text(before, lab_hint)
    if before != after:
        path.write_text(after, encoding="utf-8")
        return True
    return False


def main() -> None:
    touched = 0
    if LABS_ROOT.is_dir():
        for lab_dir in sorted(LABS_ROOT.iterdir()):
            if not lab_dir.is_dir():
                continue
            artifacts = lab_dir / "artifacts"
            if not artifacts.is_dir():
                continue
            for f in artifacts.iterdir():
                if f.suffix.lower() in {".sarif", ".json", ".xml"} and _scrub_file(f, lab_dir.name):
                    touched += 1
                    print(f"scrubbed {f.relative_to(COLLECTOR_ROOT)}")
    for root, hint in ((SELF, "self_release"), (SAMPLE, "sample_release")):
        if not root.is_dir():
            continue
        for f in root.iterdir():
            if f.suffix.lower() in {".sarif", ".json", ".xml"} and _scrub_file(f, hint):
                touched += 1
                print(f"scrubbed {f.relative_to(COLLECTOR_ROOT)}")
    print(f"done ({touched} files modified)")


if __name__ == "__main__":
    main()
