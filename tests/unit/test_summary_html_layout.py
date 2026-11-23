"""Layout guards for summary.html that do not need a browser.

The measured check (every rendered state at 375 and 721 to 1280 CSS px and in
print, sheet.scrollWidth <= sheet.clientWidth) runs in headless Chrome with
the design tools; these assertions keep the rules it depends on from being
undone in the template:

- a table can never be cut off by its sheet: the sheet scrolls, and keyboard
  users can reach it (SC 2.1.1, SC 1.4.10);
- rows become cards below the width at which the widest known table fits;
- a long unbroken value in a free-text cell wraps instead of widening the table;
- the verdict panel keeps every critical item in view and moves the rest of a
  long list behind a disclosure, so the next step stays near the top;
- the control map, the gaps and the control table read most critical first,
  and every tile and chip lands on the row it names.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest

from evidence_collector.controls.engine import evaluate_controls
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceType,
    ReleaseStatus,
)
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
    Gap,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.html import bundle_to_html
from evidence_collector.scoring.engine import build_summary

CARD_BREAKPOINT_MIN_PX = 1000
CHIPS_IN_VIEW = 4


def _evaluation(control_id: str, criticality: ControlCriticality) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=ControlFramework.NIST_SSDF,
        control_name=f"Control {control_id}",
        evaluation_status=ControlEvaluationStatus.MISSING,
        criticality=criticality,
        evidence_refs=[],
        confidence=ConfidenceLevel.LOW,
        rationale="required evidence is missing",
    )


def _not_ready_bundle(critical: int, high: int) -> EvidenceBundle:
    controls = [_evaluation(f"CRIT-{n}", ControlCriticality.CRITICAL) for n in range(critical)]
    controls += [_evaluation(f"HIGH-{n}", ControlCriticality.HIGH) for n in range(high)]
    summary = Summary(
        evidence_coverage_score=0,
        confidence_score=0,
        release_status=ReleaseStatus.NOT_READY,
        missing_critical_evidence=[f"{c.control_id}:sast_scan" for c in controls],
        total_controls=len(controls),
        controls_met=0,
        controls_partial=0,
        controls_missing=len(controls),
        controls_waived=0,
        controls_not_applicable=0,
    )
    return EvidenceBundle(
        bundle_id="bundle-layout",
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        evidence=[],
        control_evaluations=controls,
        summary=summary,
    )


def _css(html: str) -> str:
    return html[html.index("<style>") : html.index("</style>")]


def _chips(html: str) -> list[str]:
    """The missing items a panel shows, as `CONTROL:evidence_type`."""
    return [
        f"{control}:{evidence_type}"
        for control, evidence_type in re.findall(
            r'class="chip"[^>]*><b>([^<]+)</b><span>([^<]+)</span>', html
        )
    ]


def _verdict_panel(html: str) -> str:
    start = html.index('<section class="verdict')
    return html[start : html.index("</section>", start)]


def test_every_sheet_is_a_labelled_focusable_scroll_region() -> None:
    html = bundle_to_html(_not_ready_bundle(critical=2, high=3))
    sheets = re.findall(r'<div class="sheet"[^>]*>', html)
    assert sheets
    for sheet in sheets:
        assert 'role="region"' in sheet
        assert re.search(r'aria-label="[^"]+ table"', sheet)
        assert 'tabindex="0"' in sheet
    sheet_rule = re.search(r"\n  \.sheet \{[^}]*\}", _css(html))
    assert sheet_rule is not None
    assert "overflow-x: auto" in sheet_rule.group(0)
    assert "overflow: hidden" not in sheet_rule.group(0)


def test_rows_become_cards_below_the_width_of_the_widest_table() -> None:
    css = _css(bundle_to_html(_not_ready_bundle(critical=1, high=0)))
    queries = re.findall(
        r"@media screen and \(max-width: (\d+)px\) \{\s*table, tbody, tr, th, td \{ display: block; \}",
        css,
    )
    assert [int(width) for width in queries] == [CARD_BREAKPOINT_MIN_PX]


def test_free_text_cells_wrap_anywhere() -> None:
    html = bundle_to_html(_not_ready_bundle(critical=1, high=0))
    assert "td.wide, th.wide, .free { overflow-wrap: anywhere; }" in _css(html)


def test_verdict_panel_keeps_critical_items_in_view_and_folds_the_rest() -> None:
    bundle = _not_ready_bundle(critical=2, high=9)
    html = bundle_to_html(bundle)
    panel = _verdict_panel(html)
    in_view, _, folded = panel.partition('<details class="more">')
    shown = _chips(in_view)
    hidden = _chips(folded)
    assert shown == bundle.summary.missing_critical_evidence[:CHIPS_IN_VIEW]
    assert shown + hidden == bundle.summary.missing_critical_evidence
    assert f"<summary>{len(hidden)} more</summary>" in folded


def test_every_critical_item_stays_in_view_even_past_the_cap() -> None:
    bundle = _not_ready_bundle(critical=CHIPS_IN_VIEW + 2, high=3)
    in_view = _verdict_panel(bundle_to_html(bundle)).partition('<details class="more">')[0]
    critical = bundle.summary.missing_critical_evidence[: CHIPS_IN_VIEW + 2]
    assert _chips(in_view)[: len(critical)] == critical


def test_a_short_list_has_no_disclosure() -> None:
    panel = _verdict_panel(bundle_to_html(_not_ready_bundle(critical=1, high=2)))
    assert '<details class="more">' not in panel


def test_group_labels_start_their_own_line() -> None:
    css = _css(bundle_to_html(_not_ready_bundle(critical=1, high=1)))
    assert re.search(r"\n  \.chips-label \{ display: block;", css)


def _tiles(html: str) -> list[tuple[str, str]]:
    """Each tile of the control map as (row anchor, control id)."""
    return re.findall(
        r'<a class="tile"[^>]*href="#(ctl-\d+)">\s*<span class="tile-top">.*?<b>([^<]+)</b>',
        html,
        re.S,
    )


def _row_control(html: str, anchor: str) -> str:
    row = html[html.index(f'<tr role="row" id="{anchor}">') :]
    match = re.search(r'<th role="rowheader"[^>]*>\s*<code>([^<]+)</code>', row)
    assert match is not None
    return match.group(1)


def _mixed_bundle() -> EvidenceBundle:
    """Controls listed least critical first, with gaps in the same order."""
    order = [
        ("LOW-1", ControlCriticality.LOW),
        ("MED-1", ControlCriticality.MEDIUM),
        ("HIGH-1", ControlCriticality.HIGH),
        ("CRIT-1", ControlCriticality.CRITICAL),
        ("HIGH-2", ControlCriticality.HIGH),
    ]
    controls = [_evaluation(control_id, level) for control_id, level in order]
    gaps = [
        Gap(
            control_id=c.control_id, criticality=c.criticality, description=f"gap of {c.control_id}"
        )
        for c in controls
    ]
    bundle = _not_ready_bundle(critical=0, high=0)
    summary = bundle.summary.model_copy(
        update={"total_controls": len(controls), "controls_missing": len(controls)}
    )
    return bundle.model_copy(
        update={"control_evaluations": controls, "gaps": gaps, "summary": summary}
    )


def test_every_tile_links_to_the_row_of_its_control() -> None:
    html = bundle_to_html(_mixed_bundle())
    tiles = _tiles(html)
    assert [control_id for _, control_id in tiles] == [
        "CRIT-1",
        "HIGH-1",
        "HIGH-2",
        "MED-1",
        "LOW-1",
    ]
    for anchor, control_id in tiles:
        assert _row_control(html, anchor) == control_id


def test_every_missing_item_chip_links_to_the_row_of_its_control() -> None:
    html = bundle_to_html(_not_ready_bundle(critical=2, high=2))
    links = re.findall(r'<a class="chip"[^>]*href="#(ctl-\d+)"><b>([^<]+)</b>', html)
    assert len(links) == 4
    for anchor, control_id in links:
        assert _row_control(html, anchor) == control_id


def test_gaps_are_grouped_most_critical_first_with_their_weight() -> None:
    html = bundle_to_html(_mixed_bundle())
    section = html[html.index('id="gaps"') : html.index('id="controls"')]
    groups = re.findall(
        r'<div class="gapgroup g-(\w+)">\s*<h3>(\w+)<small>(\d+) · ([^<]+)</small>', section
    )
    assert [(key, label, count) for key, label, count, _ in groups] == [
        ("critical", "Critical", "1"),
        ("high", "High", "2"),
        ("medium", "Medium", "1"),
        ("low", "Low", "1"),
    ]
    assert {key: note for key, _, _, note in groups} == GAP_NOTES
    listed = re.findall(r"gap of ([A-Z]+-\d)", section)
    assert listed == ["CRIT-1", "HIGH-1", "HIGH-2", "MED-1", "LOW-1"]


GAP_NOTES = {
    "critical": "each one makes the release not_ready",
    "high": "each one keeps the release conditional at best",
    "medium": "each one keeps the release conditional at best",
    "low": "each one keeps the release conditional at best unless a waiver covers its control",
}
NOW = datetime(2026, 6, 1, tzinfo=UTC)


def _control(
    criticality: ControlCriticality,
    *,
    required: list[EvidenceType] | None = None,
    recommended: list[EvidenceType] | None = None,
) -> ControlDefinition:
    return ControlDefinition(
        control_id="CTL-1",
        framework=ControlFramework.NIST_SSDF,
        name="The only control",
        description="A control with no evidence supplied.",
        criticality=criticality,
        required_evidence_types=required or [],
        recommended_evidence_types=recommended or [],
    )


def _engine_bundle(
    control: ControlDefinition, exceptions: list[EvidenceException] | None = None
) -> EvidenceBundle:
    """Evaluate and score one control with no evidence, as `run` does."""
    evaluations, gaps = evaluate_controls(
        [control], [], exceptions=exceptions or [], application="app", release="1", now=NOW
    )
    return EvidenceBundle(
        bundle_id="bundle-engine",
        generated_at=NOW,
        application=Application(name="app", repository="acme/app"),
        release=ReleaseContext(release_id="1", commit_sha="abcdef1"),
        evidence=[],
        control_evaluations=evaluations,
        gaps=gaps,
        exceptions=exceptions or [],
        summary=build_summary([control], evaluations, gaps),
    )


def _gap_notes(html: str) -> dict[str, str]:
    return dict(
        re.findall(r'<div class="gapgroup g-(\w+)">\s*<h3>\w+<small>\d+ · ([^<]+)</small>', html)
    )


@pytest.mark.parametrize(
    ("criticality", "verdict"),
    [
        (ControlCriticality.CRITICAL, ReleaseStatus.NOT_READY),
        (ControlCriticality.HIGH, ReleaseStatus.CONDITIONAL),
        (ControlCriticality.MEDIUM, ReleaseStatus.CONDITIONAL),
        (ControlCriticality.LOW, ReleaseStatus.CONDITIONAL),
    ],
)
def test_a_lone_missing_required_gap_reads_as_the_engine_scores_it(
    criticality: ControlCriticality, verdict: ReleaseStatus
) -> None:
    bundle = _engine_bundle(_control(criticality, required=[EvidenceType.SAST_SCAN]))
    assert [gap.criticality for gap in bundle.gaps] == [criticality]
    assert bundle.summary.release_status is verdict
    html = bundle_to_html(bundle)
    assert _gap_notes(html) == {criticality.value: GAP_NOTES[criticality.value]}
    assert "never blocks" not in html


def test_a_lone_recommended_gap_is_low_and_keeps_the_release_conditional() -> None:
    bundle = _engine_bundle(_control(ControlCriticality.HIGH, recommended=[EvidenceType.SBOM]))
    assert [gap.criticality for gap in bundle.gaps] == [ControlCriticality.LOW]
    assert bundle.control_evaluations[0].evaluation_status is ControlEvaluationStatus.PARTIAL
    assert bundle.summary.release_status is ReleaseStatus.CONDITIONAL
    assert _gap_notes(bundle_to_html(bundle)) == {"low": GAP_NOTES["low"]}


def test_a_waived_gap_is_low_and_says_it_does_not_count() -> None:
    waiver = EvidenceException(
        exception_id="EXC-1",
        control_id="CTL-1",
        approver="approver@example.test",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        justification="Compensating control documented.",
    )
    control = _control(ControlCriticality.CRITICAL, required=[EvidenceType.SAST_SCAN])
    bundle = _engine_bundle(control, [waiver])
    assert [gap.criticality for gap in bundle.gaps] == [ControlCriticality.LOW]
    assert bundle.summary.release_status is ReleaseStatus.READY
    html = bundle_to_html(bundle)
    assert _gap_notes(html) == {"low": GAP_NOTES["low"]}
    assert "The control is waived, so this gap does not count against the verdict." in html


def test_every_control_keeps_its_rationale() -> None:
    bundle = _mixed_bundle()
    html = bundle_to_html(bundle)
    assert html.count("<summary>Rationale</summary>") == len(bundle.control_evaluations)
    assert html.count("<p>required evidence is missing</p>") == len(bundle.control_evaluations)


def test_the_controls_legend_shows_the_counts_the_breakdown_states() -> None:
    bundle = _mixed_bundle()
    summary = bundle.summary.model_copy(
        update={
            "controls_met": 2,
            "controls_partial": 1,
            "controls_missing": 1,
            "controls_not_applicable": 1,
        }
    )
    html = bundle_to_html(bundle.model_copy(update={"summary": summary}))
    legend = re.search(r'<p class="legend" aria-hidden="true">(.*?)</p>', html, re.S)
    breakdown = re.search(r'<div class="meta">(.*?)</div>', html, re.S)
    assert legend is not None and breakdown is not None
    shown = [
        " ".join(re.sub(r"<[^>]+>", " ", item).split())
        for item in re.findall(r"<span data-tone[^>]*>(.*?)</span>", legend.group(1), re.S)
    ]
    assert shown == ["2 met", "1 partial", "1 missing", "1 n/a"]
    assert breakdown.group(1) == " · ".join(shown)
