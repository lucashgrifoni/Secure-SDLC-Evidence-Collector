"""The verdict block `run` prints in a colour terminal.

It answers, top to bottom: what the verdict is and what it means, how the
scores and controls stand, which critical evidence is missing, what to do
next, which files were written and the exit code. The table `run` prints
everywhere else is in `_render.render_summary` and does not change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from rich.console import Console
from rich.markup import escape

from evidence_collector.application.orchestrator import BundleBuildResult
from evidence_collector.cli._terminal import (
    Glyphs,
    continuation,
    describe_mix,
    glyphs_for,
    label,
    score_bar,
    strength_mix,
)
from evidence_collector.domain.enums import ControlCriticality, ReleaseStatus
from evidence_collector.domain.models import EvidenceBundle, Summary

# Same sentences as the verdict meaning in summary.html.
MEANING: Final[dict[ReleaseStatus, str]] = {
    ReleaseStatus.READY: "Every control is met, waived or not applicable.",
    ReleaseStatus.CONDITIONAL: (
        "No critical control lacks required evidence, but at least one control is "
        "partial or missing, or supplied evidence was set aside."
    ),
    ReleaseStatus.NOT_READY: "A critical control lacks required evidence.",
}

_MISSING_HEADINGS: Final[dict[bool, tuple[str, str]]] = {
    True: ("Missing critical evidence", "each one blocks the release"),
    False: ("Missing high evidence", "each one keeps the release from ready"),
}

ATTESTATION_EXAMPLES: Final[str] = "examples/sample_release/attestations"
INDENT_ITEM: Final[str] = "    "


def render_run_view(console: Console, result: BundleBuildResult, exit_code: int) -> None:
    """Print the verdict block for a person reading a colour terminal."""
    glyphs = glyphs_for(console)
    bundle = result.bundle
    console.print(_verdict_line(bundle, glyphs), highlight=False)
    console.print(MEANING[bundle.summary.release_status], highlight=False)
    console.print()
    for line in _measures(bundle, glyphs):
        console.print(line, highlight=False)
    for line in [*_missing_evidence(bundle, glyphs), *_next_step(bundle)]:
        console.print(line, highlight=False)
    console.print()
    for line in _written_files(result):
        # Not wrapped: a path cut in two cannot be copied.
        console.print(line, highlight=False, soft_wrap=True)
    console.print(f"{label('Exit')}{exit_code}", highlight=False)


def _verdict_line(bundle: EvidenceBundle, glyphs: Glyphs) -> str:
    status = bundle.summary.release_status.value
    word = status.replace("_", " ").upper()
    return (
        f"[verdict.{status}] {word} [/]  [brand]{escape(bundle.application.name)}[/brand] "
        f"{escape(bundle.release.release_id)} "
        f"[muted]{glyphs.dot} commit {escape(bundle.release.commit_sha[:7])}[/muted]"
    )


def _measures(bundle: EvidenceBundle, glyphs: Glyphs) -> list[str]:
    summary = bundle.summary
    coverage, strength = summary.evidence_coverage_score, summary.confidence_score
    lines = [
        f"{label('Coverage')}{score_bar(coverage, glyphs)}  {coverage:>3}/100",
        f"{label('Strength')}{score_bar(strength, glyphs)}  {strength:>3}/100  "
        f"[muted]{describe_mix(strength_mix(bundle))}[/muted]",
        f"{label('Controls')}{_control_counts(summary, glyphs)}  "
        f"[muted]of {summary.total_controls}[/muted]",
    ]
    risk = summary.risk_assessment
    if risk:
        lines.append(
            label("Risk")
            + escape(
                f"{risk.mode}: presence-based verdict {risk.base_release_status.value}. "
                f"{risk.rationale}"
            )
        )
    return lines


def _control_counts(summary: Summary, glyphs: Glyphs) -> str:
    counts = (
        (summary.controls_met, "met", "status.ok"),
        (summary.controls_partial, "partial", "status.warn"),
        (summary.controls_missing, "missing", "status.bad"),
        (summary.controls_waived, "waived", "muted"),
        (summary.controls_not_applicable, "not applicable", "muted"),
    )
    parts = [f"[{style}]{count} {word}[/{style}]" for count, word, style in counts if count]
    return f" {glyphs.dot} ".join(parts) or "none"


def _missing_evidence(bundle: EvidenceBundle, glyphs: Glyphs) -> list[str]:
    critical_ids = {
        e.control_id
        for e in bundle.control_evaluations
        if e.criticality == ControlCriticality.CRITICAL
    }
    items = [_split_item(item) for item in bundle.summary.missing_critical_evidence]
    lines: list[str] = []
    for critical in (True, False):
        group = [(cid, kind) for cid, kind in items if (cid in critical_ids) is critical]
        if group:
            lines += ["", *_missing_group(group, critical, glyphs)]
    return lines


def _split_item(item: str) -> tuple[str, str]:
    """`CONTROL-ID:evidence_type`, as the summary records it, into its two parts."""
    control_id, _, kind = item.rpartition(":")
    return control_id, kind


def _missing_group(group: list[tuple[str, str]], critical: bool, glyphs: Glyphs) -> list[str]:
    heading, note = _MISSING_HEADINGS[critical]
    width = max(len(control_id) for control_id, _ in group) + 3
    rows = [
        f"{INDENT_ITEM}[status.bad]{glyphs.cross}[/status.bad] "
        f"{escape(control_id.ljust(width))}{escape(kind)}"
        for control_id, kind in group
    ]
    return [f"  [brand]{heading}[/brand] [muted]({note})[/muted]", *rows]


def _next_step(bundle: EvidenceBundle) -> list[str]:
    errors = len(bundle.collection_errors)
    missing = len(bundle.summary.missing_critical_evidence)
    if errors:
        steps = [f"fix the {_count(errors, 'input')} that failed to parse and run again"]
    elif missing:
        steps = [
            f"add the {_count(missing, 'missing item')} above and run again",
            f"[muted]examples in the project repository: {ATTESTATION_EXAMPLES}[/muted]",
        ]
    elif bundle.summary.release_status != ReleaseStatus.READY:
        steps = ["the report lists what each partial or missing control needs"]
    else:
        return []
    return ["", label("Next") + steps[0], *(continuation() + step for step in steps[1:])]


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}{'' if number == 1 else 's'}"


def _written_files(result: BundleBuildResult) -> list[str]:
    paths: list[tuple[Path | None, str]] = [
        (result.html_path, "  [muted]open this one first[/muted]"),
        (result.markdown_path, ""),
        (result.json_path, ""),
    ]
    written = [(path, note) for path, note in paths if path is not None]
    lines = []
    for index, (path, note) in enumerate(written):
        lead = label("Wrote") if index == 0 else continuation()
        name = escape(str(path))
        lines.append(f"{lead}[output]{name}[/output]{note}" if note else f"{lead}{name}")
    return lines
