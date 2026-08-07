"""Unit tests for exporters."""

from __future__ import annotations

import json
from pathlib import Path

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
    ControlEvaluation,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters import export_html, export_json, export_markdown
from evidence_collector.exporters._jinja import md_escape


def _build_bundle() -> EvidenceBundle:
    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    evidence = NormalizedEvidence(
        evidence_id="ev-1",
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name="cyclonedx", kind="sbom"),
        producer="cyclonedx",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="payments-api:2026.04.10",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id=release.release_id,
        commit_sha=release.commit_sha,
        summary="CycloneDX 1.5 with 3 components",
    )
    evaluation = ControlEvaluation(
        control_id="SSDF-PS.3",
        framework=ControlFramework.NIST_SSDF,
        control_name="Archive and protect each software release",
        evaluation_status=ControlEvaluationStatus.MET,
        criticality=ControlCriticality.CRITICAL,
        evidence_refs=["ev-1"],
        confidence=ConfidenceLevel.HIGH,
        rationale="SBOM present",
    )
    summary = Summary(
        evidence_coverage_score=100,
        confidence_score=100,
        release_status=ReleaseStatus.READY,
        total_controls=1,
        controls_met=1,
        controls_partial=0,
        controls_missing=0,
        controls_waived=0,
        controls_not_applicable=0,
    )
    return EvidenceBundle(
        bundle_id="bundle-test",
        application=app_,
        release=release,
        evidence=[evidence],
        control_evaluations=[evaluation],
        summary=summary,
    )


def test_export_json_is_deterministic(tmp_path: Path) -> None:
    bundle = _build_bundle()
    path_a = export_json(bundle, tmp_path / "a" / "bundle.json")
    path_b = export_json(bundle, tmp_path / "b" / "bundle.json")
    data_a = path_a.read_text(encoding="utf-8")
    data_b = path_b.read_text(encoding="utf-8")
    assert data_a == data_b
    assert json.loads(data_a)["bundle_id"] == "bundle-test"


def test_export_markdown(tmp_path: Path) -> None:
    bundle = _build_bundle()
    path = export_markdown(bundle, tmp_path / "report.md")
    content = path.read_text(encoding="utf-8")
    assert "Secure SDLC Evidence Report" in content
    assert "SSDF-PS.3" in content
    assert "ev-1" in content


def test_export_html(tmp_path: Path) -> None:
    bundle = _build_bundle()
    path = export_html(bundle, tmp_path / "summary.html")
    content = path.read_text(encoding="utf-8")
    assert "<html" in content
    assert "payments-api" in content
    assert "status-ready" in content


def test_export_markdown_never_glues_two_bullets_onto_one_line(tmp_path: Path) -> None:
    """Jinja `trim_blocks=True` eats the newline after a block tag (UX-01).

    Three lines of `report.md.j2` ended with an inline `{% endif %}` /
    `{% endfor %}`, so their line break was swallowed and the next bullet was
    appended to them. The canonical sample report shipped 32 such lines,
    rendering raw `- **Producer:**` in the middle of running text — in the
    human-facing deliverable the README showcases. Fixed with `+%}` whitespace
    control; this test fails if any template regains the pattern.
    """
    import re

    target = tmp_path / "report.md"
    export_markdown(_build_bundle(), target)
    glued = [
        line
        for line in target.read_text(encoding="utf-8").splitlines()
        if re.search(r"\S- \*\*(Producer|Summary|Artifact|Findings|Status|Subject)", line)
    ]
    assert glued == [], f"{len(glued)} bullet(s) glued onto the previous line: {glued[:3]}"


def test_sample_fixtures_carry_real_urls() -> None:
    r"""The canonical demo must not ship visibly corrupted URLs (FIX-02).

    `examples/sample_release/artifacts/*` carried `http./sample_release` in
    every SARIF `$schema` and `informationUri` and in the ZAP site name — dating
    back to v1.0.0. It leaked into the showcase deliverable: `report.md` from
    the README's own smoke test rendered
    `| OWASP ZAP | \`http./sample_release\` |` as the subject reference.
    """
    import re

    root = Path("examples")
    offenders = [
        f"{path}:{i}"
        for path in root.rglob("*.json")
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "http./" in line
    ] + [
        f"{path}:{i}"
        for path in root.rglob("*.sarif")
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if "http./" in line
    ]
    assert offenders == [], f"corrupted URLs in example fixtures: {offenders}"

    # And the URLs that are there parse as URLs.
    for path in root.rglob("*.sarif"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'"(?:\$schema|informationUri)":\s*"([^"]+)"', text):
            assert match.group(1).startswith("https://"), f"{path}: {match.group(1)}"


_XSS = '<script>alert("pwned")</script>'


def _hostile_bundle() -> EvidenceBundle:
    """A bundle whose strings all came from artifacts the tool did not write.

    Every value replaced here has an untrusted origin in a real run: the
    producer and summary come from a scanner, `subject_ref` from an SBOM
    component or an image reference, `control_name`/`rationale` from a custom
    catalog YAML, the application name from CLI input or CI variables.
    """
    bundle = _build_bundle()
    evidence = bundle.evidence[0].model_copy(
        update={
            "producer": _XSS,
            "subject_ref": "pkg:npm/evil|md",
            "summary": "3 components\n\n## Verdict\n\n- **Release status:** `ready`",
        }
    )
    evaluation = bundle.control_evaluations[0].model_copy(
        update={
            "control_name": _XSS,
            "rationale": "met | forged\nsecond line",
        }
    )
    return bundle.model_copy(
        update={
            "application": Application(name=_XSS, repository="acme/payments-api"),
            "evidence": [evidence],
            "control_evaluations": [evaluation],
        }
    )


def test_html_summary_escapes_untrusted_strings(tmp_path: Path) -> None:
    """`summary.html` must not execute what a scanner put in a package name.

    `select_autoescape(["html", "xml"])` matches on the template name's
    suffix, and every template here ends in `.j2` — so the HTML template was
    rendered with escaping OFF and the `default=False` fallback applied.
    Almost nothing in that page is written by this tool; a dependency named
    `<img src=x onerror=...>` or a SARIF message carrying a `<script>` tag
    reached the browser of whoever opened the release summary, and CI
    publishes that file as a build artifact.
    """
    path = export_html(_hostile_bundle(), tmp_path / "summary.html")
    content = path.read_text(encoding="utf-8")

    assert "<script>alert" not in content
    assert "&lt;script&gt;alert(&#34;pwned&#34;)&lt;/script&gt;" in content
    # The value is still shown, just inert.
    assert content.count("&lt;script&gt;") >= 2


def test_markdown_report_cannot_be_restructured_by_untrusted_strings(
    tmp_path: Path,
) -> None:
    """A value must land *in* the report, not rewrite it.

    Markdown has no autoescape: an unescaped `|` closes a table cell and
    shifts every later column, and a newline ends the row outright so whatever
    follows is parsed as top-level Markdown. That is enough to forge a
    `## Verdict` section reading `ready` inside a report whose real verdict is
    `not_ready` — from a string the tool merely copied out of an SBOM.
    """
    path = export_markdown(_hostile_bundle(), tmp_path / "report.md")
    content = path.read_text(encoding="utf-8")

    # A heading is only a heading at the start of a line. The injected text
    # survives verbatim — inline, inside the bullet it was written into — but
    # the document still has exactly the one `## Verdict` this tool wrote.
    lines = content.splitlines()
    assert [line for line in lines if line.startswith("## Verdict")] == ["## Verdict"]
    assert "## Verdict" in content
    assert "second line" in content
    assert "\nsecond line" not in content

    # Pipes are escaped, so every table row keeps its own column count.
    assert "pkg:npm/evil\\|md" in content
    assert "pkg:npm/evil|md" not in content

    rows = [line for line in content.splitlines() if line.startswith("| `ev-1`")]
    assert rows, "the evidence inventory row should be present"
    for row in rows:
        assert row.count("|") - row.count("\\|") == 7


def test_markdown_escape_filter_keeps_ordinary_values_untouched() -> None:
    """Escaping must not corrupt the overwhelmingly common clean case."""
    assert md_escape("payments-api") == "payments-api"
    assert md_escape("pkg:npm/lodash@4.17.20") == "pkg:npm/lodash@4.17.20"
    assert md_escape(None) == ""
    assert md_escape(42) == "42"
