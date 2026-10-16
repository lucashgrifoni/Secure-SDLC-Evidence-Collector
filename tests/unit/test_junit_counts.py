"""JUnit counts come from the suite attributes and the test cases both.

Suite attributes are optional in practice, and the parser used to read
nothing else: a suite that omitted ``failures`` but held a failing
``<testcase>`` reported zero failures, and a negative attribute in one suite
cancelled the failures of another. Each count is now the larger of the
attribute (negative read as 0) and the number of matching test cases under
the suite, nested suites included, so a declared count is never lowered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.domain.enums import EvidenceStatus
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_junit
from evidence_collector.parsers import parse_junit


def _write(tmp_path: Path, xml: str) -> Path:
    path = tmp_path / "junit.xml"
    path.write_text(xml, encoding="utf-8")
    return path


def test_failing_testcases_count_when_the_suite_omits_them(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    path = _write(
        tmp_path,
        '<testsuite name="s" tests="3">'
        "<testcase name='a'/>"
        "<testcase name='b'><failure message='boom'/></testcase>"
        "<testcase name='c'><error message='crash'/></testcase>"
        "</testsuite>",
    )
    parsed = parse_junit(path)
    assert (parsed.total, parsed.failures, parsed.errors) == (3, 1, 1)
    assert normalize_junit(parsed, sample_release).status == EvidenceStatus.FAILED


def test_negative_counts_do_not_cancel_failures(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    path = _write(
        tmp_path,
        "<testsuites>"
        '<testsuite name="a" tests="5" failures="4"/>'
        '<testsuite name="b" tests="6" failures="-4" errors="-1"/>'
        "</testsuites>",
    )
    parsed = parse_junit(path)
    assert (parsed.total, parsed.failures, parsed.errors) == (11, 4, 0)
    assert normalize_junit(parsed, sample_release).status == EvidenceStatus.FAILED


def test_suite_without_a_tests_attribute_counts_its_testcases(
    tmp_path: Path, sample_release: ReleaseContext
) -> None:
    path = _write(
        tmp_path, '<testsuite name="x"><testcase name="t"><failure/></testcase></testsuite>'
    )
    parsed = parse_junit(path)
    assert (parsed.total, parsed.failures) == (1, 1)
    assert normalize_junit(parsed, sample_release).status == EvidenceStatus.FAILED


def test_nested_suites_are_counted_once(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "<testsuites>"
        '<testsuite name="outer" tests="3" failures="1">'
        '<testsuite name="inner" tests="2" failures="1">'
        "<testcase name='a'/><testcase name='b'><failure/></testcase>"
        "</testsuite>"
        "<testcase name='c'><skipped/></testcase>"
        "</testsuite>"
        "</testsuites>",
    )
    parsed = parse_junit(path)
    assert (parsed.total, parsed.failures, parsed.skipped) == (3, 1, 1)


def test_declared_counts_larger_than_the_testcases_are_kept(tmp_path: Path) -> None:
    # Reporters often list only some cases; the declared totals stand.
    path = _write(
        tmp_path,
        '<testsuite name="s" tests="30" skipped="2"><testcase name="a"/>'
        "<testcase name='b'><skipped/></testcase></testsuite>",
    )
    parsed = parse_junit(path)
    assert (parsed.total, parsed.skipped) == (30, 2)


@pytest.mark.parametrize("raw_time", ["nan", "inf", "-1"])
def test_unusable_time_falls_back_to_zero_and_keeps_counts(tmp_path: Path, raw_time: str) -> None:
    path = _write(tmp_path, f'<testsuite name="s" tests="2" failures="1" time="{raw_time}"/>')
    parsed = parse_junit(path)
    assert parsed.time_seconds == 0.0
    assert (parsed.total, parsed.failures) == (2, 1)
