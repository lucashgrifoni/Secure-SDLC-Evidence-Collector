"""Building blocks for the layout `run`, `compare` and `doctor` print in a terminal.

The layout is for a person at a colour terminal. Everywhere else (a pipe, a
file, `NO_COLOR`, `TERM=dumb`, `--json-logs`) the commands print the tables they
always printed, byte for byte, because scripts and CI logs read those.

The bar, mark and arrow characters have ASCII stand-ins for a console that
cannot show them: the legacy Windows console, or a stream whose encoding is
not UTF-8.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from rich.console import Console

from evidence_collector.cli._state import is_json_logs
from evidence_collector.domain.enums import ControlEvaluationStatus
from evidence_collector.domain.models import EvidenceBundle

LABEL_WIDTH: Final[int] = 11
BAR_WIDTH: Final[int] = 20
INDENT: Final[str] = "  "


@dataclass(frozen=True)
class Glyphs:
    """The non-ASCII characters of the layout, or their ASCII stand-ins."""

    filled: str
    empty: str
    check: str
    cross: str
    dash: str
    arrow: str
    up: str
    down: str
    dot: str


UNICODE_GLYPHS: Final[Glyphs] = Glyphs("█", "░", "✓", "✗", "\u2013", "→", "▲", "▼", "·")
ASCII_GLYPHS: Final[Glyphs] = Glyphs("#", ".", "+", "x", "-", "->", "^", "v", "-")


def uses_layout(console: Console) -> bool:
    """True for an interactive colour terminal, the only place the layout is printed."""
    return (
        not is_json_logs()
        and console.is_terminal
        and console.color_system is not None
        and not console.no_color
    )


def glyphs_for(console: Console) -> Glyphs:
    """Unicode where the console can show it, ASCII on a legacy or non-UTF-8 console."""
    if console.legacy_windows or not console.encoding.lower().startswith("utf"):
        return ASCII_GLYPHS
    return UNICODE_GLYPHS


def label(text: str) -> str:
    """A muted row label padded to the column where the values start."""
    return f"{INDENT}[muted]{text.ljust(LABEL_WIDTH)}[/muted]"


def continuation() -> str:
    """The indent of a second line under a labelled row."""
    return INDENT + " " * LABEL_WIDTH


def score_bar(score: int, glyphs: Glyphs) -> str:
    """A 20-cell bar for a 0-100 score, filled part in the ok colour."""
    filled = round(max(0, min(score, 100)) * BAR_WIDTH / 100)
    return (
        f"[status.ok]{glyphs.filled * filled}[/status.ok]"
        f"[muted]{glyphs.empty * (BAR_WIDTH - filled)}[/muted]"
    )


def signed(delta: int) -> str:
    """A score delta with its sign, green when up, amber when down."""
    if delta > 0:
        return f"[status.ok]{delta:+d}[/status.ok]"
    if delta < 0:
        return f"[status.warn]{delta:+d}[/status.warn]"
    return f"[muted]{delta:+d}[/muted]"


_SCORED: Final[frozenset[ControlEvaluationStatus]] = frozenset(
    {
        ControlEvaluationStatus.MET,
        ControlEvaluationStatus.PARTIAL,
        ControlEvaluationStatus.WAIVED,
    }
)


@dataclass(frozen=True)
class StrengthMix:
    """Where the controls behind the evidence-strength score get their evidence.

    `scored` are the controls the score averages (met, partial, waived);
    `by_hand` cite at least one manually attested item, `by_tool` cite only
    collected ones, and the rest (a waiver with no evidence) cite none.
    """

    scored: int
    by_tool: int
    by_hand: int

    @property
    def without_evidence(self) -> int:
        return self.scored - self.by_tool - self.by_hand


def strength_mix(bundle: EvidenceBundle) -> StrengthMix:
    """Count the scored controls by the kind of evidence they rest on."""
    manual = {item.evidence_id for item in bundle.evidence if item.manual}
    scored = [e for e in bundle.control_evaluations if e.evaluation_status in _SCORED]
    by_hand = sum(1 for e in scored if manual.intersection(e.evidence_refs))
    by_tool = sum(1 for e in scored if e.evidence_refs and not manual.intersection(e.evidence_refs))
    return StrengthMix(scored=len(scored), by_tool=by_tool, by_hand=by_hand)


def describe_mix(mix: StrengthMix) -> str:
    """One phrase saying what the strength score is made of."""
    if mix.scored == 0:
        return "no control has evidence yet"
    if mix.by_hand == 0 and mix.without_evidence == 0:
        return f"of the {mix.scored} controls with evidence"
    parts = [
        f"{count} {kind}"
        for count, kind in (
            (mix.by_tool, "tool-backed"),
            (mix.by_hand, "attested by hand"),
            (mix.without_evidence, "waived without evidence"),
        )
        if count
    ]
    return ", ".join(parts)
