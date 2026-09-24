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
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
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
