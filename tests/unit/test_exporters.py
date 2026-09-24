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
    RawEvidenceRef,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters import export_html, export_json, export_markdown
from evidence_collector.exporters._jinja import md_code, md_escape


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


def test_bundle_id_cannot_forge_document_structure(tmp_path: Path) -> None:
    """`bundle_id` is derived from CLI input, and it reached the report unfiltered.

    `report.md.j2` line 3 rendered `{{ bundle.bundle_id }}` with no `md` filter,
    and `_default_bundle_id` builds that id by concatenating `--application` and
    `--release-id` verbatim. Both are free-form scalars with a length cap and no
    character validation, so a newline in either landed at the top level of the
    report — forging a `## Verdict` section reading `ready` above the real one.

    The same release id *is* filtered seventeen lines later in the Release
    table. The filter was applied to the table copy and missed the derived one.
    """
    # The real verdict is `not_ready`, so a `ready` status line in the output
    # can only have come from the forged id.
    honest = _build_bundle()
    blocked = honest.summary.model_copy(update={"release_status": ReleaseStatus.NOT_READY})
    forged = "\n\n## Verdict\n\n- **Release status:** `ready`\n\n**x:** "
    bundle = honest.model_copy(update={"bundle_id": f"bundle-{forged}-1", "summary": blocked})

    path = export_markdown(bundle, tmp_path / "report.md")
    content = path.read_text(encoding="utf-8")

    lines = content.splitlines()
    assert [line for line in lines if line.startswith("## Verdict")] == ["## Verdict"]
    assert not [line for line in lines if line.startswith("- **Release status:** `ready`")]
    assert "- **Release status:** `not_ready`" in content


def test_md_escape_cannot_be_defeated_by_a_pre_escaped_pipe() -> None:
    """Escaping the pipe without escaping the backslash first re-opens the cell.

    `md_escape` did `.replace("|", "\\|")`, so a value already containing a
    backslash-pipe became backslash-backslash-pipe: an *escaped backslash*
    followed by a LIVE pipe. Python-Markdown splits the row there. On the
    waiver table that pushes the real `expires_at` into the Reference column
    and promotes an attacker-chosen date into "Expires at" — an expired waiver
    reading as valid for another 74 years, from a value the tool copied out of
    a waiver file.
    """
    escaped = md_escape(r"security-lead\|2099-01-01T00:00:00+00:00\|JIRA-1")

    # No live pipe survives: every `|` is preceded by an odd number of backslashes.
    for index, char in enumerate(escaped):
        if char != "|":
            continue
        preceding = len(escaped[:index]) - len(escaped[:index].rstrip("\\"))
        assert preceding % 2 == 1, f"live pipe at {index} in {escaped!r}"


def test_md_escape_neutralises_every_character_python_treats_as_a_line_break() -> None:
    """`splitlines()` breaks on more than `\n` — so must the filter.

    U+2028, U+2029, U+0085 and U+001C-U+001E are all line boundaries to
    `str.splitlines()`, which is what every line-wise consumer of `report.md`
    uses — including this project's own structural assertions.
    """
    for raw in ("\u2028", "\u2029", "\u0085", "\x1c", "\x1d", "\x1e"):
        escaped = md_escape(f"before{raw}after")
        assert len(escaped.splitlines()) == 1, f"{raw!r} still breaks the line"
        assert "before" in escaped and "after" in escaped


def test_windows_paths_are_not_double_escaped_in_code_spans(tmp_path: Path) -> None:
    r"""CommonMark does not process backslash escapes inside a code span.

    `md_escape` doubles backslashes, which is correct and necessary in prose
    and plain table cells — and rendered literally inside backticks, where
    `report.md.j2` puts nearly every identifier and path. So every artifact
    path a Windows runner recorded read `C:\Users\...` in the human-facing
    audit deliverable. An escape applied where it is not processed does not
    make the value safer, only wrong.
    """
    windows_path = r"C:\Users\build\artifacts\sbom.cdx.json"
    bundle = _build_bundle()
    evidence = bundle.evidence[0].model_copy(
        update={
            "raw": RawEvidenceRef(artifact_path=windows_path, integrity_hash="sha256:abc"),
        }
    )

    path = export_markdown(bundle.model_copy(update={"evidence": [evidence]}), tmp_path / "r.md")
    content = path.read_text(encoding="utf-8")

    assert f"`{windows_path}`" in content
    # The doubled form is what the prose filter would have produced here.
    assert r"C:\\Users" not in content


def test_a_backtick_cannot_escape_its_code_span() -> None:
    """A backtick in the value would close the span and free the rest."""
    escaped = md_code("pkg:npm/a`b` + **bold**")

    assert "`" not in escaped
    assert "bold" in escaped


def test_a_pipe_is_still_escaped_inside_a_code_span() -> None:
    """A GFM table is split before inline code is parsed, so the pipe still cuts.

    The escape renders as a literal backslash-pipe inside the span, which is
    ugly and unavoidable — and much better than a row whose columns shift.
    """
    escaped = md_code("pkg:npm/a|b")

    assert escaped == r"pkg:npm/a\|b"


def test_md_code_neutralises_line_breaks_like_its_prose_sibling() -> None:
    for raw in ("\n", "\r", "\u2028", "\u2029", "\x85"):
        assert len(md_code(f"before{raw}after").splitlines()) == 1


# ---------------------------------------------------------------------------
# The two published reports must agree about where evidence came from
# ---------------------------------------------------------------------------


def _manual_bundle() -> EvidenceBundle:
    """A bundle whose only evidence is an operator-declared attestation.

    `producer` is the tool the operator *says* signed the artifact, which is
    exactly the field that reads as machine provenance when nothing qualifies
    it.
    """
    bundle = _build_bundle()
    declared = bundle.evidence[0].model_copy(
        update={
            "evidence_id": "att-1",
            "evidence_type": EvidenceType.ARTIFACT_SIGNATURE,
            "source": EvidenceSource(name="manual-attestation", kind="attestation"),
            "producer": "cosign",
            "manual": True,
            "summary": "Artifact signed with cosign using keyless OIDC flow",
        }
    )
    return bundle.model_copy(
        update={"evidence": [declared], "control_evaluations": [], "summary": bundle.summary}
    )


def test_a_manual_attestation_is_marked_as_one_in_both_reports(tmp_path: Path) -> None:
    """`summary.html` attributed an operator's typed claim to the named tool.

    The evidence carries `manual=True` and a `manual-attestation` source, and
    `report.md` has rendered that qualifier since it was written. The HTML
    evidence table showed only `producer` — so the same evidence read as
    "cosign signed this" in the artifact a reviewer skims and as a declared
    claim in the one they read closely. Both are published side by side from a
    single run, so they cannot be allowed to disagree about provenance.
    """
    bundle = _manual_bundle()
    markdown = export_markdown(bundle, tmp_path / "report.md").read_text(encoding="utf-8")
    html = export_html(bundle, tmp_path / "summary.html").read_text(encoding="utf-8")

    assert "manual attestation" in markdown
    assert "manual attestation" in html


def test_machine_collected_evidence_is_not_labelled_manual(tmp_path: Path) -> None:
    """The negative control: the label has to mean something.

    A marker applied to everything carries no information, and a test that
    only asserts its presence would pass just as happily.
    """
    bundle = _build_bundle()
    assert bundle.evidence[0].manual is False

    markdown = export_markdown(bundle, tmp_path / "report.md").read_text(encoding="utf-8")
    html = export_html(bundle, tmp_path / "summary.html").read_text(encoding="utf-8")

    assert "manual attestation" not in markdown
    assert "manual attestation" not in html
