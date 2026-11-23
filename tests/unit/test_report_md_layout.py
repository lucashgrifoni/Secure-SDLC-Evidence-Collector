"""Layout of report.md: verdict first, what to produce next, the record last.

The report reads top-down as a decision: the title names the application and
release, the quote under it gives the verdict, a one-row table the scores, then
the gaps to close and the controls, most critical first. The record of where the
verdict came from (application, release, catalog, bundle), the evidence
inventory and the per-control rationales sit in collapsed `<details>` blocks at
the end. Nothing the report carried before the redesign may be dropped, only
moved, and no value copied from an artifact may change that structure.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from markdown_it import MarkdownIt

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    CatalogRef,
    CollectionError,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
    EvidenceSource,
    Gap,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
    RiskAssessment,
    Summary,
)
from evidence_collector.exporters._jinja import md_code, md_escape
from evidence_collector.exporters.markdown import bundle_to_markdown

_RELEASE = ReleaseContext(
    release_id="2026.04.10",
    commit_sha="abcdef1234567890",
    branch="release-train",
    pipeline_run_id="run-4242",
    build_id="build-77",
    artifact_digest="sha256:" + "d" * 64,
    tag="v2026.04.10",
)


def _evaluation(
    control_id: str,
    criticality: ControlCriticality,
    status: ControlEvaluationStatus,
    *,
    framework: ControlFramework = ControlFramework.NIST_SSDF,
    refs: tuple[str, ...] = (),
    exception_refs: tuple[str, ...] = (),
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=framework,
        control_name=f"Name of {control_id}",
        evaluation_status=status,
        criticality=criticality,
        evidence_refs=list(refs),
        confidence=ConfidenceLevel.HIGH if refs else ConfidenceLevel.LOW,
        rationale=f"Rationale written for {control_id}.",
        exception_refs=list(exception_refs),
    )


def _gap(
    control_id: str,
    criticality: ControlCriticality,
    evidence_type: EvidenceType | None,
    remediation: str | None,
) -> Gap:
    return Gap(
        control_id=control_id,
        evidence_type=evidence_type,
        criticality=criticality,
        description=f"Gap description for {control_id}.",
        remediation=remediation,
    )


def _exception(exception_id: str, control_id: str, expires_at: datetime) -> EvidenceException:
    return EvidenceException(
        exception_id=exception_id,
        control_id=control_id,
        approver=f"approver-of-{exception_id}",
        approved_at=datetime(2026, 1, 2, tzinfo=UTC),
        expires_at=expires_at,
        justification=f"Justification recorded for {exception_id}.",
        reference=f"TICKET-{exception_id}",
    )


def _evidence() -> list[NormalizedEvidence]:
    shared = {
        "release_id": _RELEASE.release_id,
        "commit_sha": _RELEASE.commit_sha,
        "confidence": ConfidenceLevel.HIGH,
    }
    sbom = NormalizedEvidence(
        evidence_id="sbom-1",
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name="cyclonedx", kind="sbom", version="1.5"),
        producer="cyclonedx-cli",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="pkg:generic/acme/payments-api@2026.04.10",
        status=EvidenceStatus.GENERATED,
        summary="SBOM with 3 components",
        findings_count={"components": 3},
        raw=RawEvidenceRef(
            artifact_path="artifacts/sbom.cdx.json", integrity_hash="sha256:" + "a" * 64
        ),
        **shared,
    )
    approval = NormalizedEvidence(
        evidence_id="approval-1",
        evidence_type=EvidenceType.RELEASE_APPROVAL,
        source=EvidenceSource(name="attestation", kind="manual"),
        producer="release-board",
        subject_type=SubjectType.RELEASE,
        subject_ref="release-2026.04.10",
        status=EvidenceStatus.PASSED,
        manual=True,
        **shared,
    )
    return [sbom, approval]


def _full_bundle() -> EvidenceBundle:
    """A not_ready bundle with every optional field the report shows set.

    Controls and gaps are deliberately out of criticality order, with two of
    the same rank in each list, so the sort and its stability are both visible.
    """
    controls = [
        _evaluation(
            "CTL-LOW", ControlCriticality.LOW, ControlEvaluationStatus.MET, refs=("sbom-1",)
        ),
        _evaluation("CTL-CRIT-A", ControlCriticality.CRITICAL, ControlEvaluationStatus.MISSING),
        _evaluation(
            "CTL-MED",
            ControlCriticality.MEDIUM,
            ControlEvaluationStatus.PARTIAL,
            framework=ControlFramework.OWASP_SAMM,
            refs=("sbom-1",),
        ),
        _evaluation(
            "CTL-HIGH",
            ControlCriticality.HIGH,
            ControlEvaluationStatus.WAIVED,
            framework=ControlFramework.ORG_INTERNAL,
            exception_refs=("EXC-APPLIED",),
        ),
        _evaluation(
            "CTL-CRIT-B",
            ControlCriticality.CRITICAL,
            ControlEvaluationStatus.MET,
            refs=("sbom-1", "approval-1"),
        ),
    ]
    gaps = [
        _gap("CTL-MED", ControlCriticality.LOW, EvidenceType.ARTIFACT_SIGNATURE, None),
        _gap(
            "CTL-CRIT-A", ControlCriticality.CRITICAL, EvidenceType.CODE_REVIEW, "Attach a review."
        ),
        _gap("CTL-MED", ControlCriticality.MEDIUM, EvidenceType.THREAT_MODEL, "Attach a model."),
        _gap("CTL-UNKNOWN", ControlCriticality.CRITICAL, None, "Attach anything."),
    ]
    summary = Summary(
        evidence_coverage_score=61,
        confidence_score=73,
        release_status=ReleaseStatus.NOT_READY,
        missing_critical_evidence=["CTL-CRIT-A:code_review"],
        total_controls=5,
        controls_met=2,
        controls_partial=1,
        controls_missing=1,
        controls_waived=1,
        controls_not_applicable=0,
        risk_assessment=RiskAssessment(
            mode="epss-weighted",
            epss_percentile_threshold=0.9,
            exploitable_cve_count=0,
            kev_cve_count=0,
            kev_ransomware_cve_count=0,
            high_epss_cve_count=0,
            base_release_status=ReleaseStatus.NOT_READY,
            rationale="No CVE crossed a threshold.",
        ),
    )
    return EvidenceBundle(
        bundle_id="bundle-full-1",
        bundle_version="2.1.0",
        generated_at=datetime(2026, 6, 1, 12, 30, tzinfo=UTC),
        application=Application(
            name="payments-api",
            repository="acme/payments-api",
            environment="staging",
            owner_team="team-payments",
        ),
        release=_RELEASE,
        catalog=CatalogRef(
            origin="custom", name="org-catalog.yaml", sha256="c" * 64, control_count=5
        ),
        evidence=_evidence(),
        control_evaluations=controls,
        gaps=gaps,
        exceptions=[
            _exception("EXC-APPLIED", "CTL-HIGH", datetime(2026, 12, 31, tzinfo=UTC)),
            _exception("EXC-EXPIRED", "CTL-CRIT-A", datetime(2026, 2, 1, tzinfo=UTC)),
        ],
        collection_errors=[CollectionError(path="artifacts/broken.sarif", reason="not valid JSON")],
        summary=summary,
    )


def _render(markdown: str) -> str:
    """Render as a CommonMark engine with GFM tables and raw HTML allowed."""
    return str(MarkdownIt("commonmark").enable("table").render(markdown))


def _shows(content: str, value: object) -> bool:
    text = str(value)
    return md_escape(text) in content or md_code(text) in content


def _table_rows(content: str, heading: str) -> list[list[str]]:
    """Cells of the first table after ``heading``, header and divider skipped."""
    section = content[content.index(f"\n{heading}") + 1 :]
    rows: list[list[str]] = []
    for line in section.splitlines()[1:]:
        if line.startswith("|"):
            rows.append([cell.strip() for cell in line.strip("|").split(" | ")])
        elif rows:
            break
    return rows[2:]


# ---------------------------------------------------------------------------
# Order
# ---------------------------------------------------------------------------


def test_sections_come_in_the_approved_order() -> None:
    content = bundle_to_markdown(_full_bundle())
    landmarks = [
        line
        for line in content.splitlines()
        if line.startswith(("# ", "## ", "> **", "| Evidence coverage", "<details>"))
    ]
    assert landmarks == [
        "# Secure SDLC Evidence Report: payments-api 2026.04.10",
        "> **Not ready** (`not_ready`). A critical control lacks required evidence.",
        "> **Risk-weighted verdict (`epss-weighted`):** presence-based verdict `not_ready`."
        " No CVE crossed a threshold.",
        "| Evidence coverage | Evidence strength | Controls |",
        "> **1 supplied input(s) could not be read.**",
        "## What to produce (4 gaps)",
        "<details><summary>How to close each gap</summary>",
        "## Controls (5)",
        "## Approved exceptions",
        "## Exceptions not in force",
        "<details><summary>Evidence inventory (2)</summary>",
        "<details><summary>Record: application, release, catalog, bundle</summary>",
        "<details><summary>Rationale per control</summary>",
    ]


def test_the_scores_row_uses_the_display_labels() -> None:
    content = bundle_to_markdown(_full_bundle())
    assert "| 61/100 | 73/100 | 2 met · 1 partial · 1 missing · 1 waived · 0 n/a |" in content


def test_gaps_are_listed_most_critical_first_keeping_bundle_order_within_a_rank() -> None:
    rows = _table_rows(bundle_to_markdown(_full_bundle()), "## What to produce")
    assert [(row[0], row[1], row[2]) for row in rows] == [
        ("**critical**", "`CTL-CRIT-A` Name of CTL-CRIT-A", "`code_review`"),
        ("**critical**", "`CTL-UNKNOWN`", "`-`"),
        ("**medium**", "`CTL-MED` Name of CTL-MED", "`threat_model`"),
        ("**low**", "`CTL-MED` Name of CTL-MED", "`artifact_signature`"),
    ]


def test_controls_are_listed_most_critical_first_keeping_bundle_order_within_a_rank() -> None:
    rows = _table_rows(bundle_to_markdown(_full_bundle()), "## Controls")
    assert [(row[0], row[1], row[2]) for row in rows] == [
        ("`CTL-CRIT-A` Name of CTL-CRIT-A", "critical", "**missing**"),
        ("`CTL-CRIT-B` Name of CTL-CRIT-B", "critical", "**met**"),
        ("`CTL-HIGH` Name of CTL-HIGH", "high", "**waived**"),
        ("`CTL-MED` Name of CTL-MED", "medium", "**partial**"),
        ("`CTL-LOW` Name of CTL-LOW", "low", "**met**"),
    ]


def test_a_report_without_gaps_says_so() -> None:
    bundle = _full_bundle()
    clean = bundle.model_copy(
        update={
            "gaps": [],
            "summary": bundle.summary.model_copy(update={"missing_critical_evidence": []}),
        }
    )
    content = bundle_to_markdown(clean)
    assert "## What to produce (0 gaps)" in content
    assert "No gaps detected." in content
    assert "**Missing critical/high evidence:** none" in content
    assert "How to close each gap" not in content


def test_a_single_gap_is_not_pluralised() -> None:
    bundle = _full_bundle()
    content = bundle_to_markdown(bundle.model_copy(update={"gaps": bundle.gaps[:1]}))
    assert "## What to produce (1 gap)" in content


# ---------------------------------------------------------------------------
# Nothing dropped
# ---------------------------------------------------------------------------


def test_every_value_the_report_carried_before_the_redesign_is_still_there() -> None:
    bundle = _full_bundle()
    content = bundle_to_markdown(bundle)
    app, release, catalog = bundle.application, bundle.release, bundle.catalog
    assert catalog is not None
    risk = bundle.summary.risk_assessment
    assert risk is not None

    values: list[object] = [
        bundle.bundle_id,
        bundle.bundle_version,
        bundle.generated_at.isoformat(),
        *(app.name, app.repository, app.environment, app.owner_team),
        *(release.release_id, release.commit_sha, release.branch, release.pipeline_run_id),
        *(release.build_id, release.artifact_digest, release.tag),
        *(catalog.origin, catalog.name, catalog.sha256, catalog.control_count),
        *bundle.summary.missing_critical_evidence,
        *(risk.mode, risk.base_release_status.value, risk.rationale),
    ]
    for error in bundle.collection_errors:
        values += [error.path, error.reason]
    for evaluation in bundle.control_evaluations:
        values += [evaluation.control_id, evaluation.control_name, evaluation.rationale]
        values += [evaluation.framework.value, *evaluation.evidence_refs]
    for gap in bundle.gaps:
        values += [gap.control_id, gap.criticality.value, gap.description]
        values += [gap.evidence_type.value if gap.evidence_type else "-", gap.remediation or ""]
    for exception in bundle.exceptions:
        values += [exception.exception_id, exception.control_id, exception.approver]
        values += [exception.expires_at.isoformat()]
    applied = bundle.exceptions[0]
    values += [applied.approved_at.isoformat(), applied.reference, applied.justification]
    for item in bundle.evidence:
        values += [item.evidence_id, item.evidence_type.value, item.status.value, item.producer]
        values += [item.subject_ref, item.subject_type.value, item.source.name, item.source.kind]
    sbom = bundle.evidence[0]
    assert sbom.raw is not None
    values += [sbom.source.version, sbom.summary, sbom.raw.artifact_path, sbom.raw.integrity_hash]

    missing = [value for value in values if not _shows(content, value)]
    assert missing == []

    for phrase in (
        "`not_ready`",
        "61/100",
        "73/100",
        "2 met · 1 partial · 1 missing · 1 waived · 0 n/a",
        "components=3",
        "manual attestation",
        "No remediation hint available.",
        "not the catalog shipped with the tool",
        "Every verdict above is relative to the control catalog below.",
        "1 supplied input(s) could not be read.",
        "Supplied with the evidence but not applied to this release.",
        "| `EXC-EXPIRED` | `CTL-CRIT-A` | approver-of-EXC-EXPIRED | 2026-02-01T00:00:00+00:00 | expired",
    ):
        assert phrase in content, phrase


def test_a_custom_catalog_is_flagged_under_the_verdict_not_only_in_the_record() -> None:
    content = bundle_to_markdown(_full_bundle())
    quote = content[: content.index("| Evidence coverage")]
    assert "custom control catalog, **not the catalog shipped with the tool**" in quote


def test_the_builtin_catalog_raises_no_flag() -> None:
    bundle = _full_bundle()
    assert bundle.catalog is not None
    builtin = bundle.catalog.model_copy(update={"origin": "builtin"})
    content = bundle_to_markdown(bundle.model_copy(update={"catalog": builtin}))
    assert "not the catalog shipped" not in content


# ---------------------------------------------------------------------------
# Rendering: GFM shows Markdown inside <details> only after a blank line
# ---------------------------------------------------------------------------


def test_html_blocks_and_headings_are_separated_by_blank_lines() -> None:
    lines = bundle_to_markdown(_full_bundle()).splitlines()
    needs_blank_before = [
        index for index, line in enumerate(lines) if line.startswith("#") or line == "</details>"
    ][1:]
    openers = [index for index, line in enumerate(lines) if line.startswith("<details>")]

    assert len(needs_blank_before) > 10
    assert len(openers) == 4
    assert [lines[i] for i in openers if not lines[i].endswith("</summary>")] == []
    assert [lines[i] for i in needs_blank_before if lines[i - 1] != ""] == []
    assert [lines[i] for i in openers if lines[i + 1] != ""] == []


def test_markdown_inside_the_details_blocks_is_rendered() -> None:
    html = _render(bundle_to_markdown(_full_bundle()))
    blocks = re.findall(r"<details><summary>(.*?)</summary>(.*?)</details>", html, re.S)
    assert [summary for summary, _ in blocks] == [
        "How to close each gap",
        "Evidence inventory (2)",
        "Record: application, release, catalog, bundle",
        "Rationale per control",
    ]
    bodies = dict(blocks)
    assert "<ul>" in bodies["How to close each gap"]
    assert "<table>" in bodies["Evidence inventory (2)"]
    assert "<h3><code>sbom-1</code>" in bodies["Evidence inventory (2)"]
    assert "<td>Bundle ID</td>" in bodies["Record: application, release, catalog, bundle"]
    assert "<strong><code>CTL-LOW</code>" in bodies["Rationale per control"]


# ---------------------------------------------------------------------------
# Injection: a value copied from an artifact must not change the structure
# ---------------------------------------------------------------------------

_BREAKOUT = "x</details>\n\n## Controls (0)\n\n<script>alert(1)</script>\n<details><summary>y"


def _hostile(bundle: EvidenceBundle) -> EvidenceBundle:
    evaluation = bundle.control_evaluations[1].model_copy(
        update={"control_name": _BREAKOUT, "rationale": _BREAKOUT}
    )
    gap = bundle.gaps[1].model_copy(
        update={"control_id": "CTL-CRIT-A", "description": _BREAKOUT, "remediation": _BREAKOUT}
    )
    error = CollectionError(path=_BREAKOUT, reason=_BREAKOUT)
    return bundle.model_copy(
        update={
            "application": bundle.application.model_copy(update={"name": "app\n# Forged | x"}),
            "release": bundle.release.model_copy(update={"release_id": "<b>r</b>"}),
            "control_evaluations": [*bundle.control_evaluations[:1], evaluation],
            "gaps": [gap],
            "collection_errors": [error],
        }
    )


def test_untrusted_values_cannot_close_a_details_block_or_forge_sections() -> None:
    content = bundle_to_markdown(_hostile(_full_bundle()))
    html = _render(content)

    assert "<script" not in html
    assert "<b>" not in html
    assert html.count("<details>") == html.count("</details>") == 4
    assert re.findall(r"<h1>(.*?)</h1>", html) == [
        "Secure SDLC Evidence Report: app # Forged | x &lt;b&gt;r&lt;/b&gt;"
    ]
    assert re.findall(r"<h2>(.*?)</h2>", html) == [
        "What to produce (1 gap)",
        "Controls (2)",
        # The waived control is not in this bundle, so no waiver was applied.
        "Exceptions not in force",
    ]
    # The hostile control name sits inside its own cell in both tables.
    for heading in ("## What to produce", "## Controls"):
        for row in _table_rows(content, heading):
            assert len(row) == (3 if heading.startswith("## What") else 5)
