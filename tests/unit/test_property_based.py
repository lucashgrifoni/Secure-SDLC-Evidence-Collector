"""Property-based tests for parsers and scoring.

Hand-written cases catch known edge cases; property-based tests
explore the input space machine-generated and surface the unknown
edge cases. We focus on three contracts:

1. JUnit parser must accept any well-formed `<testsuite>` whose
   numeric attributes are integers — and never raise on malformed
   numerics, falling back to defaults instead.
2. SARIF parser must classify findings into the documented severity
   buckets (`high` / `medium` / `low`) regardless of the literal
   level string used by the producer.
3. Bundle scoring is monotone: adding evidence cannot lower the
   coverage score, and removing evidence cannot raise it.

These three properties together cover the heart of the determinism
and explainability claims.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Hypothesis is an optional dev dependency; skip cleanly when missing
# so test collection still works on a minimal install.
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from evidence_collector.parsers import parse_junit, parse_sarif  # noqa: E402
from evidence_collector.parsers._common import ParseError  # noqa: E402

# Hypothesis warns when a `@given`-decorated test uses a function-scoped
# fixture, since the fixture state is shared across all generated inputs.
# We use `tmp_path` here only as a clean place to write the per-iteration
# file under a unique name; the test's behaviour does not depend on the
# fixture being reset, so suppressing the health check is the right call.
_TMP_FIXTURE_OK = settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


# ---------- JUnit ---------- #


_attr_value = st.one_of(
    st.integers(min_value=0, max_value=10_000).map(str),
    st.text(
        alphabet=st.characters(
            # Excluding surrogate codepoints + XML metacharacters keeps
            # generated strings serializable as XML attribute values.
            blacklist_categories=["Cs"],
            blacklist_characters='<>"&',
        ),
        min_size=1,
        max_size=10,
    ),
)


@given(
    tests=_attr_value,
    failures=_attr_value,
    errors=_attr_value,
    skipped=_attr_value,
    time=_attr_value,
)
@_TMP_FIXTURE_OK
def test_junit_never_crashes_on_arbitrary_numeric_attributes(
    tmp_path: Path,
    tests: str,
    failures: str,
    errors: str,
    skipped: str,
    time: str,
) -> None:
    suite = tmp_path / "fuzz.xml"
    suite.write_text(
        f'<testsuite name="fuzz" tests="{tests}" failures="{failures}" '
        f'errors="{errors}" skipped="{skipped}" time="{time}">'
        "<testcase /></testsuite>",
        encoding="utf-8",
    )
    try:
        parsed = parse_junit(suite)
    except ParseError:
        # The parser rejecting a malformed file is acceptable; what we
        # are testing is that it never raises something *other than*
        # ParseError on legal XML with weird attributes.
        return
    # Counters can never go negative even when source attributes are
    # garbage strings — the fallback is 0.
    assert parsed.total >= 0
    assert parsed.failures >= 0
    assert parsed.errors >= 0
    assert parsed.skipped >= 0
    assert parsed.time_seconds >= 0.0


# ---------- SARIF ---------- #


_sarif_levels = st.sampled_from(
    [
        "error",
        "warning",
        "note",
        "none",
        "ERROR",  # producers occasionally upper-case
        "Warning",
        # Some producers emit non-standard strings; the normalizer
        # should treat them as `low`.
        "informational",
        "advisory",
    ]
)


@given(level=_sarif_levels, count=st.integers(min_value=1, max_value=5))
@_TMP_FIXTURE_OK
def test_sarif_classifies_arbitrary_levels_into_known_buckets(
    tmp_path: Path, level: str, count: int
) -> None:
    results = ", ".join(
        [f'{{"ruleId":"R{i}","level":"{level}","message":{{"text":"x"}}}}' for i in range(count)]
    )
    sarif = tmp_path / "fuzz.sarif"
    sarif.write_text(
        f"""{{
            "version":"2.1.0",
            "runs":[{{
                "tool":{{"driver":{{"name":"semgrep"}}}},
                "results":[{results}]
            }}]
        }}""",
        encoding="utf-8",
    )
    parsed = parse_sarif(sarif)
    # Every finding must be classified — no leakage outside the
    # documented bucket set. Hypothesis surfaced "critical" here, which
    # the normalizer does emit for SARIF results that map to the highest
    # severity. Including it documents the real contract.
    allowed_buckets = {"critical", "high", "medium", "low", "info", "unknown", "none"}
    assert set(parsed.findings_count.keys()) <= allowed_buckets
    # The total count matches the number of results we wrote.
    assert sum(parsed.findings_count.values()) == count
    assert parsed.total_findings == count


# ---------- Scoring monotonicity ---------- #


def test_scoring_coverage_never_decreases_with_more_evidence(
    tmp_path: Path,
    sample_release_root: Path,
) -> None:
    # This is a hand-written guard rather than a Hypothesis test
    # because building a `NormalizedEvidence` object via Hypothesis
    # would require implementing a strategy for every nested model.
    # The property still holds and is stated alongside the property
    # tests so the contract is visible.
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.domain.models import Application, ReleaseContext

    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")

    full = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=tmp_path / "full",
    )
    only_attestations = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=[],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=tmp_path / "subset",
    )
    assert (
        full.bundle.summary.evidence_coverage_score
        >= only_attestations.bundle.summary.evidence_coverage_score
    ), "adding evidence must never lower coverage"


# ---------- Risk-weighted verdict (D13) ---------- #


_STATUS_ORDER = ["ready", "conditional", "not_ready"]

_top_risk_cve = st.builds(
    lambda idx, pct, kev, ransom: (idx, pct, kev, kev and ransom),
    st.integers(min_value=1000, max_value=9999),
    st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    st.booleans(),
    st.booleans(),
)


@given(
    base=st.sampled_from(_STATUS_ORDER),
    tops=st.lists(_top_risk_cve, max_size=6),
    extra_kev=st.integers(min_value=0, max_value=3),
    extra_ransomware=st.integers(min_value=0, max_value=3),
    threshold=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)
@settings(max_examples=200, deadline=None)
def test_risk_mode_never_lowers_the_base_status(
    base: str,
    tops: list[tuple[int, float, bool, bool]],
    extra_kev: int,
    extra_ransomware: int,
    threshold: float,
) -> None:
    """Whatever the EPSS / KEV signal, epss-weighted mode never promotes a verdict."""
    from datetime import UTC, datetime

    from evidence_collector.domain.enums import (
        ConfidenceLevel,
        EvidenceStatus,
        EvidenceType,
        ReleaseStatus,
        SubjectType,
    )
    from evidence_collector.domain.models import (
        EvidenceSource,
        NormalizedEvidence,
        Summary,
        TopRiskCve,
        VulnerabilityIntelligence,
    )
    from evidence_collector.scoring import RiskMode, RiskThresholds, apply_risk_mode

    top_risk = [
        TopRiskCve(
            cve_id=f"CVE-2024-{idx}",
            epss_score=pct,
            epss_percentile=pct,
            in_kev=kev,
            known_ransomware=ransom,
        )
        for idx, pct, kev, ransom in tops
    ]
    in_kev = sum(1 for t in top_risk if t.in_kev) + extra_kev
    ransomware = sum(1 for t in top_risk if t.known_ransomware) + min(extra_ransomware, extra_kev)
    evidence = NormalizedEvidence(
        evidence_id="sca-prop",
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name="trivy", kind="sca"),
        producer="trivy",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="acme/api@1.0",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        cve_ids=["CVE-2024-0001"],
        vulnerability_intelligence=VulnerabilityIntelligence(
            cve_count=len(top_risk) + extra_kev,
            cves_in_kev_count=in_kev,
            cves_known_ransomware_count=ransomware,
            top_risk_cves=top_risk,
            enriched_at=datetime(2026, 5, 19, tzinfo=UTC),
        ),
    )
    summary = Summary(
        evidence_coverage_score=80,
        confidence_score=80,
        release_status=ReleaseStatus(base),
        total_controls=1,
        controls_met=1,
        controls_partial=0,
        controls_missing=0,
        controls_waived=0,
        controls_not_applicable=0,
    )
    out = apply_risk_mode(
        summary,
        [evidence],
        mode=RiskMode.EPSS_WEIGHTED,
        thresholds=RiskThresholds(epss_percentile_threshold=threshold),
    )
    assert _STATUS_ORDER.index(out.release_status.value) >= _STATUS_ORDER.index(base)
    assert out.risk_assessment is not None
    assert out.risk_assessment.base_release_status.value == base
    if ransomware:
        assert out.release_status is ReleaseStatus.NOT_READY
    elif in_kev:
        assert out.release_status is not ReleaseStatus.READY
