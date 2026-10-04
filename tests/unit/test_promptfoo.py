"""promptfoo eval output (`promptfoo eval -o results.json`) becomes `ai_safety_eval`.

promptfoo has no formal schema, so the parser pins the envelope's
`results.version == 3`, reads the aggregate `stats`, and walks each result
row tolerating a missing `gradingResult`, which error rows leave out. Unlike
lm-eval, promptfoo decides pass or fail per test, so the evidence carries
that verdict: any failed test fails the evidence, and a run where every row
errored proves nothing and is invalid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import ConfidenceLevel, EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_promptfoo
from evidence_collector.parsers import parse_promptfoo
from evidence_collector.parsers._common import ParseError


def _output(successes: int = 2, failures: int = 0, errors: int = 0) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for _ in range(successes):
        rows.append(
            {
                "success": True,
                "score": 1.0,
                "gradingResult": {
                    "pass": True,
                    "score": 1.0,
                    "componentResults": [{"pass": True, "assertion": {"type": "contains"}}],
                },
            }
        )
    for _ in range(failures):
        rows.append(
            {
                "success": False,
                "score": 0.0,
                "gradingResult": {
                    "pass": False,
                    "score": 0.0,
                    "componentResults": [
                        {"pass": False, "assertion": {"type": "not-contains"}},
                        {"pass": True, "assertion": {"type": "contains"}},
                    ],
                },
            }
        )
    for _ in range(errors):
        rows.append({"success": False, "score": 0.0, "error": "provider timeout"})
    return {
        "evalId": "eval-abc-2026-09-24",
        "results": {
            "version": 3,
            "timestamp": "2026-09-24T18:00:00Z",
            "stats": {"successes": successes, "failures": failures, "errors": errors},
            "prompts": [{"provider": "openai:gpt-5"}],
            "results": rows,
        },
        "config": {"description": "support bot guardrails"},
        "shareableUrl": None,
    }


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.09.24", commit_sha="abcdef1234567890")


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_the_envelope_and_assertions_are_read(tmp_path: Path) -> None:
    parsed = parse_promptfoo(_write(tmp_path / "results.json", _output(2, 1, 1)))

    assert parsed.eval_id == "eval-abc-2026-09-24"
    assert (parsed.successes, parsed.failures, parsed.errors) == (2, 1, 1)
    assert parsed.rows == 4
    assert (parsed.assertions_passed, parsed.assertions_failed) == (3, 1)
    assert parsed.failed_assertion_types == {"not-contains": 1}


@pytest.mark.parametrize(
    ("counts", "status"),
    [
        ((3, 0, 0), EvidenceStatus.PASSED),
        ((2, 1, 0), EvidenceStatus.FAILED),
        ((2, 0, 1), EvidenceStatus.FAILED),
        ((0, 0, 2), EvidenceStatus.INVALID),
    ],
)
def test_the_verdict_follows_the_test_outcomes(
    tmp_path: Path, counts: tuple[int, int, int], status: EvidenceStatus
) -> None:
    parsed = parse_promptfoo(_write(tmp_path / "results.json", _output(*counts)))
    evidence = normalize_promptfoo(parsed, _release())

    assert evidence.evidence_type == EvidenceType.AI_SAFETY_EVAL
    assert evidence.status == status
    assert evidence.findings_count == {"failed": counts[1], "errors": counts[2]}


def test_another_output_version_is_refused(tmp_path: Path) -> None:
    doc = _output()
    doc["results"]["version"] = 4
    with pytest.raises(ParseError, match="version 4"):
        parse_promptfoo(_write(tmp_path / "results.json", doc))


def test_the_collector_detects_promptfoo_output(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "results.json", _output())
    _write(artifacts / "other.json", {"results": {"version": 3}})

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert [e.evidence_type for e in report.evidence] == [EvidenceType.AI_SAFETY_EVAL]
    assert report.evidence[0].producer == "promptfoo"


@pytest.mark.parametrize(("failures", "expected"), [(0, "met"), (1, "missing")])
def test_a_failed_test_keeps_the_ai_safety_control_from_being_met(
    tmp_path: Path, failures: int, expected: str
) -> None:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.controls.catalog import bundled_catalog_path
    from evidence_collector.domain.models import Application

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "results.json", _output(2, failures, 0))

    result = run_pipeline(
        Application(name="support-bot", repository="acme/support-bot"),
        _release(),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
        catalog_path=bundled_catalog_path("catalog-ai.yaml"),
    )
    assert result.json_path is not None
    bundle = json.loads(result.json_path.read_text(encoding="utf-8"))
    [safety] = [e for e in bundle["control_evaluations"] if e["control_id"] == "AI-SAFETY-EVAL"]
    assert safety["evaluation_status"] == expected


@pytest.mark.parametrize(
    "row",
    [
        {"success": False, "gradingResult": {"componentResults": 5}},
        {"success": False, "gradingResult": {"componentResults": True}},
        {"success": False, "gradingResult": ["not", "a", "dict"]},
        "not a row",
    ],
)
def test_a_malformed_row_does_not_stop_the_other_files(tmp_path: Path, row: object) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    bad = _output(1, 1, 0)
    bad["results"]["results"].append(row)
    _write(artifacts / "bad.json", bad)
    _write(artifacts / "good.json", _output())

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    producers = [e.producer for e in report.evidence]
    assert producers.count("promptfoo") == 2


@pytest.mark.parametrize("errors", ["1", True, -1, 1.5, None])
def test_a_malformed_error_count_is_refused_not_read_as_zero(
    tmp_path: Path, errors: object
) -> None:
    """A present but invalid count must not turn into "no errors" and pass the evidence."""
    doc = _output(3, 0, 0)
    doc["results"]["stats"]["errors"] = errors
    with pytest.raises(ParseError, match="errors"):
        parse_promptfoo(_write(tmp_path / "results.json", doc))


def test_a_missing_error_count_means_none(tmp_path: Path) -> None:
    doc = _output(3, 0, 0)
    del doc["results"]["stats"]["errors"]
    assert parse_promptfoo(_write(tmp_path / "results.json", doc)).errors == 0


def _leaf(passed: bool, kind: str, value: str) -> dict[str, Any]:
    return {
        "pass": passed,
        "score": 1 if passed else 0,
        "assertion": {"type": kind, "value": value},
    }


def _assert_set_row(berlin_passes: bool) -> dict[str, Any]:
    """One row in the shape promptfoo 0.123.1 writes for an `assert-set`.

    The set's aggregate result comes first, with no `assertion` of its own
    and its children nested under `componentResults`; promptfoo then repeats
    those children flat at the top level, next to the other assertions.
    """
    children = [_leaf(True, "contains", "Paris"), _leaf(berlin_passes, "contains", "Berlin")]
    aggregate = {
        "pass": berlin_passes,
        "score": 1 if berlin_passes else 0.5,
        "componentResults": children,
        "metadata": {"assertionSet": {"type": "assert-set", "assertionCount": 2}},
    }
    return {
        "success": berlin_passes,
        "score": 1 if berlin_passes else 0.75,
        "gradingResult": {
            "pass": berlin_passes,
            "componentResults": [aggregate, *children, _leaf(True, "not-contains", "London")],
        },
    }


@pytest.mark.parametrize(
    ("berlin_passes", "tally", "failed_types"),
    [(False, (2, 1), {"contains": 1}), (True, (3, 0), {})],
)
def test_an_assert_set_counts_each_of_its_assertions_once(
    tmp_path: Path, berlin_passes: bool, tally: tuple[int, int], failed_types: dict[str, int]
) -> None:
    doc = _output(0, 0, 0)
    doc["results"]["stats"].update(successes=int(berlin_passes), failures=int(not berlin_passes))
    doc["results"]["results"] = [_assert_set_row(berlin_passes)]

    parsed = parse_promptfoo(_write(tmp_path / "results.json", doc))

    assert (parsed.assertions_passed, parsed.assertions_failed) == tally
    assert parsed.failed_assertion_types == failed_types


def _unasserted_row() -> dict[str, Any]:
    """A test with no `assert`: promptfoo passes it with nothing graded."""
    return {
        "success": True,
        "score": 1,
        "gradingResult": {"pass": True, "score": 1, "reason": "No assertions"},
    }


def test_a_run_that_graded_no_assertion_is_invalid_not_passed(tmp_path: Path) -> None:
    doc = _output(2, 0, 0)
    doc["results"]["results"] = [_unasserted_row(), _unasserted_row()]

    evidence = normalize_promptfoo(
        parse_promptfoo(_write(tmp_path / "results.json", doc)), _release()
    )

    assert evidence.status == EvidenceStatus.INVALID
    assert evidence.confidence == ConfidenceLevel.LOW
    assert evidence.summary == "promptfoo: 2 passed, 0 failed, 0 errored; no assertions were graded"
    assert (evidence.metadata["tests_passed"], evidence.metadata["assertions_passed"]) == (2, 0)


def test_a_run_with_some_asserted_tests_still_passes(tmp_path: Path) -> None:
    doc = _output(1, 0, 0)
    doc["results"]["stats"]["successes"] = 2
    doc["results"]["results"].append(_unasserted_row())

    evidence = normalize_promptfoo(
        parse_promptfoo(_write(tmp_path / "results.json", doc)), _release()
    )

    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.HIGH
    assert evidence.summary == "promptfoo: 2 passed, 0 failed, 0 errored"


def test_a_run_that_graded_no_assertion_does_not_meet_the_ai_safety_control(
    tmp_path: Path,
) -> None:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.controls.catalog import bundled_catalog_path
    from evidence_collector.domain.models import Application

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    doc = _output(2, 0, 0)
    doc["results"]["results"] = [_unasserted_row(), _unasserted_row()]
    _write(artifacts / "results.json", doc)

    result = run_pipeline(
        Application(name="support-bot", repository="acme/support-bot"),
        _release(),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
        catalog_path=bundled_catalog_path("catalog-ai.yaml"),
    )
    assert result.json_path is not None
    bundle = json.loads(result.json_path.read_text(encoding="utf-8"))
    [safety] = [e for e in bundle["control_evaluations"] if e["control_id"] == "AI-SAFETY-EVAL"]
    assert safety["evaluation_status"] == "missing"


def test_a_single_top_level_assertion_is_counted(tmp_path: Path) -> None:
    """A lone assertion can sit in gradingResult itself, with no componentResults."""
    doc = _output(1, 0, 0)
    doc["results"]["results"] = [
        {"success": True, "score": 1, "gradingResult": _leaf(True, "contains", "Paris")}
    ]

    evidence = normalize_promptfoo(
        parse_promptfoo(_write(tmp_path / "results.json", doc)), _release()
    )

    assert evidence.metadata["assertions_passed"] == 1
    assert evidence.status == EvidenceStatus.PASSED
    assert evidence.confidence == ConfidenceLevel.HIGH


@pytest.mark.parametrize(("child_passes", "tally"), [(True, (1, 0)), (False, (0, 1))])
def test_a_custom_assertion_with_nested_results_counts_once(
    tmp_path: Path, child_passes: bool, tally: tuple[int, int]
) -> None:
    """A JavaScript assertion may return componentResults that are not repeated flat."""
    custom = _leaf(child_passes, "javascript", "output.length > 0")
    custom["componentResults"] = [{"pass": child_passes, "score": 1, "reason": "sub-check"}]
    doc = _output(int(child_passes), int(not child_passes), 0)
    doc["results"]["results"] = [
        {
            "success": child_passes,
            "gradingResult": {"pass": child_passes, "componentResults": [custom]},
        }
    ]

    parsed = parse_promptfoo(_write(tmp_path / "results.json", doc))

    assert (parsed.assertions_passed, parsed.assertions_failed) == tally
    assert parsed.failed_assertion_types == ({} if child_passes else {"javascript": 1})
