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
  long list behind a disclosure, so the next step stays near the top.
"""

from __future__ import annotations

import re

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    ReleaseStatus,
)
from evidence_collector.domain.models import (
    Application,
    ControlEvaluation,
    EvidenceBundle,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.html import bundle_to_html

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
    shown = re.findall(r'class="chip"[^>]*><code>([^<]+)</code>', in_view)
    hidden = re.findall(r'class="chip"[^>]*><code>([^<]+)</code>', folded)
    assert shown == bundle.summary.missing_critical_evidence[:CHIPS_IN_VIEW]
    assert shown + hidden == bundle.summary.missing_critical_evidence
    assert f"<summary>{len(hidden)} more</summary>" in folded


def test_every_critical_item_stays_in_view_even_past_the_cap() -> None:
    bundle = _not_ready_bundle(critical=CHIPS_IN_VIEW + 2, high=3)
    in_view = _verdict_panel(bundle_to_html(bundle)).partition('<details class="more">')[0]
    for item in bundle.summary.missing_critical_evidence[: CHIPS_IN_VIEW + 2]:
        assert f"<code>{item}</code>" in in_view


def test_a_short_list_has_no_disclosure() -> None:
    panel = _verdict_panel(bundle_to_html(_not_ready_bundle(critical=1, high=2)))
    assert '<details class="more">' not in panel


def test_group_labels_start_their_own_line() -> None:
    css = _css(bundle_to_html(_not_ready_bundle(critical=1, high=1)))
    assert re.search(r"\.why \.sub \{ display: block;", css)
