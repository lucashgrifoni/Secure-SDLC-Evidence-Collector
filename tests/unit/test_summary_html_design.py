"""Contract of the summary.html design: self-contained, deterministic, escaped.

The page is opened from a CI artifact or a mail attachment, often offline and
sometimes in a browser that blocks remote content, so it must load nothing
from anywhere. It is a pure rendering of `bundle.json`: two renderings of the
same bundle are the same bytes, and nothing here may reach `bundle.json` or
`report.md`. Every bundle string stays a text node, so a scanner message
cannot become markup.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import (
    Application,
    EvidenceBundle,
    EvidenceException,
    ReleaseContext,
    RiskAssessment,
)
from evidence_collector.exporters._jinja import get_environment
from evidence_collector.exporters.html import bundle_to_html

TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "src/evidence_collector/exporters/templates/summary.html.j2"
)
DIGEST = "sha256:" + "1" * 64
COMMIT = "abcdef1234567890abcdef1234567890abcdef12"


def _release(**provenance: str) -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha=COMMIT, **provenance)


def _run(
    output_dir: Path, sample_release_root: Path, *, with_artifacts: bool, **provenance: str
) -> EvidenceBundle:
    run_pipeline(
        application=Application(
            name="payments-api", repository="acme/payments-api", owner_team="team-owner-marker"
        ),
        release=_release(**provenance),
        artifacts_dirs=[sample_release_root / "artifacts"] if with_artifacts else [],
        attestations_dirs=[sample_release_root / "attestations"] if with_artifacts else [],
        exceptions_dirs=[sample_release_root / "exceptions"],
        output_dir=output_dir,
        artifact_root=sample_release_root.parent.parent,
    )
    return EvidenceBundle.model_validate_json(
        (output_dir / "bundle.json").read_text(encoding="utf-8")
    )


@pytest.fixture(scope="module")
def ready_bundle(tmp_path_factory: pytest.TempPathFactory) -> EvidenceBundle:
    root = Path(__file__).resolve().parents[2] / "examples" / "sample_release"
    return _run(
        tmp_path_factory.mktemp("ready"),
        root,
        with_artifacts=True,
        tag="v2026.04.10",
        pipeline_run_id="run-4242",
        build_id="build-77",
        artifact_digest=DIGEST,
    )


@pytest.fixture(scope="module")
def not_ready_bundle(tmp_path_factory: pytest.TempPathFactory) -> EvidenceBundle:
    root = Path(__file__).resolve().parents[2] / "examples" / "sample_release"
    return _run(tmp_path_factory.mktemp("not_ready"), root, with_artifacts=False)


@pytest.fixture(params=["ready", "not_ready"])
def bundle(
    request: pytest.FixtureRequest, ready_bundle: EvidenceBundle, not_ready_bundle: EvidenceBundle
) -> EvidenceBundle:
    return ready_bundle if request.param == "ready" else not_ready_bundle


def _style(html: str) -> str:
    return html[html.index("<style>") : html.index("</style>")]


def test_the_fixtures_cover_both_ends_of_the_verdict(
    ready_bundle: EvidenceBundle, not_ready_bundle: EvidenceBundle
) -> None:
    assert ready_bundle.summary.release_status is ReleaseStatus.READY
    assert not_ready_bundle.summary.release_status is ReleaseStatus.NOT_READY
    assert not_ready_bundle.gaps


def test_the_page_loads_no_external_resource(bundle: EvidenceBundle) -> None:
    html = bundle_to_html(bundle)
    assert "<script" not in html.lower()
    assert "<iframe" not in html.lower()
    assert "<img" not in html.lower()
    style = _style(html)
    assert "url(" not in style
    assert "@import" not in style
    assert "@font-face" not in style
    for href in re.findall(r'\bhref="([^"]*)"', html):
        assert href.startswith(("#", "data:")), href
    for src in re.findall(r'\bsrc="([^"]*)"', html):
        assert src.startswith("data:"), src
    assert re.search(
        r"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none';", html
    )


def test_brand_fonts_come_from_font_stacks_only(bundle: EvidenceBundle) -> None:
    style = _style(bundle_to_html(bundle))
    assert '--sans: "Space Grotesk", ui-sans-serif' in style
    assert '--mono: "JetBrains Mono", ui-monospace' in style


def test_two_renderings_of_the_same_bundle_are_identical(bundle: EvidenceBundle) -> None:
    reloaded = EvidenceBundle.model_validate_json(bundle.model_dump_json())
    assert bundle_to_html(bundle) == bundle_to_html(reloaded)


def test_the_template_never_bypasses_autoescape() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    assert "|safe" not in source.replace(" ", "")
    assert "Markup(" not in source
    assert "{% autoescape" not in source
    autoescape = get_environment().autoescape
    assert callable(autoescape)
    assert autoescape("summary.html.j2") is True


def test_a_hostile_string_in_a_link_target_stays_inert(not_ready_bundle: EvidenceBundle) -> None:
    hostile = '"><script>alert(1)</script>'
    evaluation = not_ready_bundle.control_evaluations[0].model_copy(
        update={"evidence_refs": [hostile], "control_id": hostile}
    )
    bundle = not_ready_bundle.model_copy(
        update={"control_evaluations": [evaluation, *not_ready_bundle.control_evaluations[1:]]}
    )
    html = bundle_to_html(bundle)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_the_verdict_class_appears_once_in_the_panel_only(bundle: EvidenceBundle) -> None:
    html = bundle_to_html(bundle)
    status = bundle.summary.release_status.value
    assert html.count(f"status-{status}") == 1
    assert re.search(rf'<section class="verdict[^"]*status-{status}', html)
    for other in {"ready", "conditional", "not_ready"} - {status}:
        assert f"status-{other}" not in html


def test_the_verdict_reads_as_a_word_and_a_heading(bundle: EvidenceBundle) -> None:
    html = bundle_to_html(bundle)
    assert "<main" in html
    assert re.search(r"<h2[^>]*>Release status</h2>", html)
    assert f"<code>{bundle.summary.release_status.value}</code>" in html


def test_the_scores_say_what_they_measure(bundle: EvidenceBundle) -> None:
    html = bundle_to_html(bundle)
    assert "Weighted share of the required and recommended evidence" in html
    assert "backed by manually attested evidence counts one level lower" in html


def test_release_provenance_is_shown(ready_bundle: EvidenceBundle) -> None:
    html = bundle_to_html(ready_bundle)
    for value in (COMMIT, "v2026.04.10", DIGEST, "run-4242", "build-77"):
        assert value in html, value


def test_absent_provenance_reads_not_recorded(not_ready_bundle: EvidenceBundle) -> None:
    assert "not recorded" in bundle_to_html(not_ready_bundle)


def test_private_and_per_file_details_stay_out_of_the_page(ready_bundle: EvidenceBundle) -> None:
    waiver = EvidenceException(
        exception_id="EXC-PRIVATE-1",
        control_id="SSDF-PS.3",
        approver="approver@example.test",
        approved_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        justification="justification-marker: accepted until the vendor ships a fix",
    )
    bundle = ready_bundle.model_copy(update={"exceptions": [*ready_bundle.exceptions, waiver]})
    html = bundle_to_html(bundle)
    assert "team-owner-marker" not in html
    assert "justification-marker" not in html
    assert "2026-01-01" not in html
    for item in bundle.evidence:
        if item.raw is not None:
            if item.raw.artifact_path:
                assert item.raw.artifact_path not in html
            if item.raw.integrity_hash:
                assert item.raw.integrity_hash not in html


def test_gap_descriptions_show_code_not_backticks(not_ready_bundle: EvidenceBundle) -> None:
    assert any("`" in gap.description for gap in not_ready_bundle.gaps)
    html = bundle_to_html(not_ready_bundle)
    body = html[html.index("<body") :]
    assert "`" not in body


def test_every_status_pill_carries_a_word_and_an_icon(bundle: EvidenceBundle) -> None:
    html = bundle_to_html(bundle)
    pills = re.findall(r'<span class="pill[^"]*"[^>]*>(.*?)</span>', html, re.S)
    assert pills
    for pill in pills:
        assert "<svg" in pill
        assert re.sub(r"<[^>]+>", "", pill).strip()


def test_optional_footer_values_render_escaped_when_given(ready_bundle: EvidenceBundle) -> None:
    template = get_environment().get_template("summary.html.j2")
    html = template.render(
        bundle=ready_bundle,
        collector_version="<b>9.9.9</b>",
        bundle_digest=DIGEST,
        ignored_inputs=["a.txt", "b.txt"],
    )
    assert "&lt;b&gt;9.9.9&lt;/b&gt;" in html
    assert f"sdlc-evidence verify bundle.json --expected {DIGEST}" in html
    assert "2 file(s) in the artifact directories matched no parser" in html
    assert "a.txt" not in html


def _with_risk(
    bundle: EvidenceBundle, *, verdict: ReleaseStatus, exploitable: int, rationale: str
) -> EvidenceBundle:
    assessment = RiskAssessment(
        mode="epss-weighted",
        epss_percentile_threshold=0.7,
        exploitable_cve_count=exploitable,
        kev_cve_count=0,
        kev_ransomware_cve_count=0,
        high_epss_cve_count=exploitable,
        base_release_status=ReleaseStatus.READY,
        rationale=rationale,
    )
    summary = bundle.summary.model_copy(
        update={"release_status": verdict, "risk_assessment": assessment}
    )
    return bundle.model_copy(update={"summary": summary})


def test_anchor_drift_after_a_neutral_risk_mode_is_not_credited_to_risk(
    ready_bundle: EvidenceBundle,
) -> None:
    """Risk mode kept `ready`; the anchor-drift check made it `conditional`."""
    html = bundle_to_html(
        _with_risk(
            ready_bundle,
            verdict=ReleaseStatus.CONDITIONAL,
            exploitable=0,
            rationale="Risk mode requested but no vulnerability intelligence was present.",
        )
    )
    assert "The risk-weighted rule set this verdict" not in html
    assert "decides the verdict" not in html


def test_a_risk_downgrade_is_credited_to_risk(ready_bundle: EvidenceBundle) -> None:
    html = bundle_to_html(
        _with_risk(
            ready_bundle,
            verdict=ReleaseStatus.CONDITIONAL,
            exploitable=1,
            rationale="1 exploitable CVE(s); release downgraded to conditional.",
        )
    )
    assert "The risk-weighted rule set this verdict" in html
    assert "decides the verdict" in html
