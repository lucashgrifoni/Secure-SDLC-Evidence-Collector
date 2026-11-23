"""The diff `compare` prints in a colour terminal.

It leads with the verdict movement and its direction, then the score deltas,
then only the controls that moved, one per line with an arrow; the unchanged
ones are folded into a single line. The tables `compare` prints everywhere
else stay in `commands/compare.py` and do not change.
"""

from __future__ import annotations

from typing import Final, cast

from rich.console import Console
from rich.markup import escape

from evidence_collector.application.compare import BundleComparison, ControlDelta
from evidence_collector.cli._exit_codes import exit_code_for_status
from evidence_collector.cli._terminal import Glyphs, glyphs_for, label, signed, strength_mix
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import EvidenceBundle

INDENT_ITEM: Final[str] = "    "


def render_compare_view(
    console: Console,
    baseline: EvidenceBundle,
    candidate: EvidenceBundle,
    comparison: BundleComparison,
) -> None:
    """Print the diff for a person reading a colour terminal."""
    glyphs = glyphs_for(console)
    lines = [
        _headline(baseline, candidate, comparison, glyphs),
        "",
        *_score_deltas(baseline, candidate, comparison, glyphs),
        "",
        *_control_movement(comparison, glyphs),
    ]
    for line in lines:
        console.print(line, highlight=False)


def _release_name(bundle: EvidenceBundle) -> str:
    return f"{bundle.application.name} {bundle.release.release_id}"


def _headline(
    baseline: EvidenceBundle,
    candidate: EvidenceBundle,
    comparison: BundleComparison,
    glyphs: Glyphs,
) -> str:
    before, after = _release_name(baseline), _release_name(candidate)
    name = before if before == after else f"{before} {glyphs.arrow} {after}"
    return (
        f"[brand]{escape(name)}[/brand]   "
        f"{_badge(comparison.before_release_status)} {glyphs.arrow} "
        f"{_badge(comparison.after_release_status)}   "
        f"{_direction(comparison.before_release_status, comparison.after_release_status, glyphs)}"
    )


def _badge(status: ReleaseStatus) -> str:
    return f"[verdict.{status.value}] {status.value} [/]"


def _direction(before: ReleaseStatus, after: ReleaseStatus, glyphs: Glyphs) -> str:
    # The exit code ranks verdicts worst-last: the arrow can never disagree with it.
    rank_before, rank_after = exit_code_for_status(before), exit_code_for_status(after)
    if rank_after < rank_before:
        return f"[status.ok]{glyphs.up} improved[/status.ok]"
    if rank_after > rank_before:
        return f"[status.bad]{glyphs.down} regressed[/status.bad]"
    return "[muted]= unchanged[/muted]"


def _score_deltas(
    baseline: EvidenceBundle,
    candidate: EvidenceBundle,
    comparison: BundleComparison,
    glyphs: Glyphs,
) -> list[str]:
    before, after = baseline.summary, candidate.summary
    coverage = (
        f"{label('Coverage')}{before.evidence_coverage_score:>3} {glyphs.arrow} "
        f"{after.evidence_coverage_score:>3}   {signed(comparison.coverage_delta)}"
    )
    strength = (
        f"{label('Strength')}{before.confidence_score:>3} {glyphs.arrow} "
        f"{after.confidence_score:>3}   {signed(comparison.confidence_delta)}"
    )
    by_hand_before, by_hand_after = (strength_mix(b).by_hand for b in (baseline, candidate))
    if by_hand_after != by_hand_before:
        strength += (
            f"  [muted]controls attested by hand {by_hand_before} {glyphs.arrow} "
            f"{by_hand_after}[/muted]"
        )
    return [coverage, strength]


def _control_movement(comparison: BundleComparison, glyphs: Glyphs) -> list[str]:
    controls = cast(dict[str, list[str]], comparison.to_dict()["controls"])
    improved, regressed = set(controls["improved"]), set(controls["regressed"])
    drifted = set(controls["catalog_drift"])
    moved = [d for d in comparison.control_deltas if d.category != "unchanged"]
    unchanged = controls["unchanged"]
    other = len(moved) - len(improved) - len(regressed)
    counts = [
        f"[status.ok]{len(improved)} improved[/status.ok]",
        f"[status.bad]{len(regressed)} regressed[/status.bad]" if regressed else "0 regressed",
        *([f"{other} changed"] if other else []),
        f"[muted]{len(unchanged)} unchanged[/muted]",
    ]
    width = max((len(d.control_id) for d in moved), default=0) + 3
    rows = [_control_row(d, improved, regressed, drifted, width, glyphs) for d in moved]
    if unchanged:
        rows.append(f"{INDENT_ITEM}[muted]= {escape(', '.join(unchanged))}[/muted]")
    return [f"  [brand]Controls[/brand]   {f' {glyphs.dot} '.join(counts)}", *rows]


def _control_row(
    delta: ControlDelta,
    improved: set[str],
    regressed: set[str],
    drifted: set[str],
    width: int,
    glyphs: Glyphs,
) -> str:
    if delta.control_id in improved:
        mark = f"[status.ok]{glyphs.up}[/status.ok]"
    elif delta.control_id in regressed:
        mark = f"[status.bad]{glyphs.down}[/status.bad]"
    else:
        mark = f"[muted]{glyphs.dot}[/muted]"
    before = delta.before.value if delta.before else "absent"
    after = delta.after.value if delta.after else "absent"
    catalog = "  [status.warn](catalog)[/status.warn]" if delta.control_id in drifted else ""
    return (
        f"{INDENT_ITEM}{mark} {escape(delta.control_id.ljust(width))}"
        f"{before} {glyphs.arrow} {after}{catalog}"
    )
