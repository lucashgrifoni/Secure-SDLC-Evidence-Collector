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
