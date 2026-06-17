#!/usr/bin/env python3
"""Fail CI if the project version disagrees across its sources of truth.

release-please bumps the version in several files in lock-step. ADR-0013
records that release-please owns versioning; this gate turns a silent drift
between those files — the class of mistake behind the historical
``release 1.3.0`` regression that needed a manual realign to ``2.0.0`` — into
a red check instead of letting it reach a published tag.

Checked sources (all must agree):

* ``pyproject.toml`` -> ``[project].version``
* ``src/evidence_collector/__init__.py`` -> ``__version__``
* ``.github/.release-please-manifest.json`` -> the ``"."`` entry
* ``CHANGELOG.md`` -> the first released ``## [x.y.z]`` heading
  (the ``## [Unreleased]`` heading is skipped on purpose)

The git tag is intentionally not consulted here: release-please derives the
tag from these files, so keeping the files honest is what prevents a bad tag.

Exit code 0 when every source agrees, 1 otherwise (with a diff on stderr).
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def dunder_version() -> str:
    text = (ROOT / "src" / "evidence_collector" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""", text, re.MULTILINE)
    if match is None:
        raise ValueError("__version__ not found in src/evidence_collector/__init__.py")
    return match.group(1)


def manifest_version() -> str:
    path = ROOT / ".github" / ".release-please-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return str(data["."])


def changelog_version() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for match in re.finditer(r"^##\s*\[([^\]]+)\]", text, re.MULTILINE):
        label = match.group(1).strip()
        if label.lower() == "unreleased":
            continue
        return label
    raise ValueError("no released version heading found in CHANGELOG.md")


def main() -> int:
    sources = {
        "pyproject.toml": pyproject_version(),
        "src/evidence_collector/__init__.py": dunder_version(),
        ".github/.release-please-manifest.json": manifest_version(),
        "CHANGELOG.md (top release)": changelog_version(),
    }
    if len(set(sources.values())) == 1:
        print(f"Version consistency OK: {next(iter(sources.values()))}")
        return 0

    print("Version drift detected across sources of truth:", file=sys.stderr)
    width = max(len(name) for name in sources)
    for name, version in sources.items():
        print(f"  {name:<{width}} = {version}", file=sys.stderr)
    print(
        "\nThese must match. release-please normally keeps them in sync; if you "
        "edited one by hand, realign the others (or let release-please regenerate).",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
