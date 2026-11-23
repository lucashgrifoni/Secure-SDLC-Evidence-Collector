"""The checklist `doctor` prints in a colour terminal.

Required checks and optional ones are separate groups. An optional item that
is not set gets a neutral dash, not a green mark, and the closing line counts
them. The table `doctor` prints everywhere else stays in `commands/doctor.py`
and does not change; neither does `--json`.
"""

from __future__ import annotations

from typing import Final

from rich.console import Console
from rich.markup import escape

from evidence_collector.cli._preflight import CheckResult
from evidence_collector.cli._terminal import Glyphs, glyphs_for

INDENT_ITEM: Final[str] = "    "
NAME_WIDTH: Final[int] = 19
IMPORT_PREFIX: Final[str] = "Import: "
OPTIONAL_SUFFIX: Final[str] = " (optional)"

# How `_preflight` words an optional item it did not find.
_NOT_SET_PREFIXES: Final[tuple[str, ...]] = ("absent", "not installed")

# Short names and wording for the checks `_preflight` runs today. A check not
# listed here is shown with its own label and detail.
_NAMES: Final[dict[str, str]] = {
    "Python version": "Python",
    "Write permission in cwd": "Write permission",
}
_OPTIONAL_WORDING: Final[dict[str, tuple[str, str]]] = {
    "GitHub token": (
        "set [muted]{dot} used by --pull-request and --workflow-run[/muted]",
        "not set [muted]{dot} --pull-request and --workflow-run call the API\n"
        f"{' ' * (len(INDENT_ITEM) + 2 + NAME_WIDTH)}"
        "without it: rate limits, no private repositories[/muted]",
    ),
    "GitLab token": (
        "set [muted]{dot} only the library API reads it[/muted]",
        "not set [muted]{dot} only the library API reads it[/muted]",
    ),
    "cosign": ("found", "not installed [muted]{dot} only needed for signed releases[/muted]"),
}


def render_doctor_view(console: Console, results: list[CheckResult]) -> None:
    """Print the checklist for a person reading a colour terminal."""
    glyphs = glyphs_for(console)
    required = [r for r in results if not r[0].endswith(OPTIONAL_SUFFIX)]
    optional = [r for r in results if r[0].endswith(OPTIONAL_SUFFIX)]
    not_set = sum(1 for _, _, detail in optional if not _is_set(detail))
    lines = [
        "[brand]sdlc-evidence doctor[/brand]",
        "",
        "  [brand]Required[/brand]",
        *_required_rows(required, glyphs),
        "",
        "  [brand]Optional[/brand]",
        *(_optional_row(label, detail, glyphs) for label, _, detail in optional),
        "",
        _closing_line(required, not_set),
    ]
    for line in lines:
        console.print(line, highlight=False)


def _is_set(detail: str) -> bool:
    return not detail.startswith(_NOT_SET_PREFIXES)


def _row(mark: str, name: str, detail: str) -> str:
    return f"{INDENT_ITEM}{mark} {escape(name.ljust(NAME_WIDTH))}{detail}"


def _required_rows(required: list[CheckResult], glyphs: Glyphs) -> list[str]:
    imports = [r for r in required if r[0].startswith(IMPORT_PREFIX)]
    rows = []
    for label, ok, detail in required:
        if label.startswith(IMPORT_PREFIX):
            if label == imports[0][0]:
                rows.extend(_library_rows(imports, glyphs))
            continue
        rows.append(_row(_mark(ok, glyphs), _NAMES.get(label, label), _detail(label, ok, detail)))
    return rows


def _library_rows(imports: list[CheckResult], glyphs: Glyphs) -> list[str]:
    """One line for the libraries that import, one per library that does not."""
    names = [label.removeprefix(IMPORT_PREFIX) for label, _, _ in imports]
    failed = [(label, detail) for label, ok, detail in imports if not ok]
    if not failed:
        return [_row(_mark(True, glyphs), "Libraries", escape(", ".join(names)))]
    return [
        _row(_mark(False, glyphs), "Library", escape(f"{label.removeprefix(IMPORT_PREFIX)}: {why}"))
        for label, why in failed
    ]


def _detail(label: str, ok: bool, detail: str) -> str:
    if label == "Python version":
        return f"{escape(detail.split(' ', 1)[0])} [muted](needs 3.12 or newer)[/muted]"
    if ok and label == "Schema export":
        return "ok"
    if ok and label == "Write permission in cwd":
        return "current folder"
    return escape(detail)


def _optional_row(label: str, detail: str, glyphs: Glyphs) -> str:
    name = label.removesuffix(OPTIONAL_SUFFIX)
    is_set = _is_set(detail)
    present, absent = _OPTIONAL_WORDING.get(name, (escape(detail), escape(detail)))
    wording = (present if is_set else absent).replace("{dot}", glyphs.dot)
    mark = _mark(True, glyphs) if is_set else f"[muted]{glyphs.dash}[/muted]"
    return _row(mark, name, wording)


def _mark(ok: bool, glyphs: Glyphs) -> str:
    if ok:
        return f"[status.ok]{glyphs.check}[/status.ok]"
    return f"[status.bad]{glyphs.cross}[/status.bad]"


def _closing_line(required: list[CheckResult], not_set: int) -> str:
    failed = sum(1 for _, ok, _ in required if not ok)
    if failed:
        return f"  [status.bad]{failed} required check(s) failed.[/status.bad]"
    line = "  [status.ok]All required checks passed.[/status.ok]"
    if not_set:
        noun = "item is" if not_set == 1 else "items are"
        line += f" [muted]{not_set} optional {noun} not set.[/muted]"
    return line
