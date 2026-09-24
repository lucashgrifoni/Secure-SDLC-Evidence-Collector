"""Inspect (UK AI Security Institute) eval logs become `ai_safety_eval` evidence.

Inspect writes a JSON log (`--log-format json`, or `inspect log convert`)
whose `version` is 2. A run that finished with `status: success` is evidence
the evaluation happened; a run that errored, was cancelled or never finished
is not, and must not satisfy the AI catalog's safety-evaluation control.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType, SubjectType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_inspect_eval
from evidence_collector.parsers import parse_inspect_eval
from evidence_collector.parsers._common import ParseError


def _log(status: str = "success", version: int = 2) -> dict[str, Any]:
    return {
        "version": version,
        "status": status,
        "eval": {
            "task": "inspect_evals/xstest",
            "task_version": 0,
            "model": "anthropic/claude-sonnet-5",
            "created": "2026-09-20T10:00:00+00:00",
        },
        "results": {
            "total_samples": 250,
            "completed_samples": 250,
            "scores": [
                {
                    "name": "refusal_rate",
                    "metrics": {
                        "accuracy": {"name": "accuracy", "value": 0.93},
                        "stderr": {"name": "stderr", "value": 0.016},
                    },
                }
            ],
        },
        "stats": {"started_at": "2026-09-20T10:00:00+00:00"},
    }


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.09.24", commit_sha="abcdef1234567890")


def _write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_a_successful_log_is_read(tmp_path: Path) -> None:
    parsed = parse_inspect_eval(_write(tmp_path / "logs.json", _log()))

    assert parsed.task == "inspect_evals/xstest"
    assert parsed.model == "anthropic/claude-sonnet-5"
    assert parsed.status == "success"
    assert parsed.metrics == {"refusal_rate/accuracy": 0.93, "refusal_rate/stderr": 0.016}
    assert (parsed.total_samples, parsed.completed_samples) == (250, 250)


def test_a_successful_run_is_a_safety_eval_for_the_model(tmp_path: Path) -> None:
    evidence = normalize_inspect_eval(
        parse_inspect_eval(_write(tmp_path / "logs.json", _log())), _release()
    )

    assert evidence.evidence_type == EvidenceType.AI_SAFETY_EVAL
    assert evidence.subject_type == SubjectType.AI_MODEL
    assert evidence.subject_ref == "anthropic/claude-sonnet-5"
    assert evidence.status == EvidenceStatus.GENERATED
    assert evidence.metadata["inspect_task"] == "inspect_evals/xstest"
    assert evidence.metadata["metrics"]["refusal_rate/accuracy"] == 0.93


@pytest.mark.parametrize("status", ["error", "cancelled", "started"])
def test_a_run_that_did_not_succeed_is_invalid(tmp_path: Path, status: str) -> None:
    evidence = normalize_inspect_eval(
        parse_inspect_eval(_write(tmp_path / "logs.json", _log(status))), _release()
    )

    assert evidence.status == EvidenceStatus.INVALID
    assert status in (evidence.summary or "")


def test_another_log_version_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="version 3"):
        parse_inspect_eval(_write(tmp_path / "logs.json", _log(version=3)))


def test_the_collector_detects_an_inspect_log(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "2026-09-20T10-00-00_xstest.json", _log())
    _write(artifacts / "other.json", {"version": 2, "status": "success"})

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert [e.evidence_type for e in report.evidence] == [EvidenceType.AI_SAFETY_EVAL]


@pytest.mark.parametrize(("status", "expected"), [("success", "met"), ("error", "missing")])
def test_only_a_successful_run_meets_the_ai_safety_control(
    tmp_path: Path, status: str, expected: str
) -> None:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.controls.catalog import bundled_catalog_path
    from evidence_collector.domain.models import Application

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "xstest.json", _log(status))

    result = run_pipeline(
        Application(name="triage-model", repository="acme/triage-model"),
        _release(),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
        catalog_path=bundled_catalog_path("catalog-ai.yaml"),
    )
    assert result.json_path is not None
    bundle = json.loads(result.json_path.read_text(encoding="utf-8"))
    [safety] = [e for e in bundle["control_evaluations"] if e["control_id"] == "AI-SAFETY-EVAL"]
    assert safety["evaluation_status"] == expected


def test_non_finite_metric_values_are_skipped(tmp_path: Path) -> None:
    """Python's json reads NaN and Infinity; a metric without a real value is dropped."""
    log = _log()
    raw = json.dumps(log).replace("0.016", "NaN").replace("0.93", "Infinity")
    path = tmp_path / "logs.json"
    path.write_text(raw, encoding="utf-8")

    assert parse_inspect_eval(path).metrics == {}


@pytest.mark.parametrize(
    "hostile",
    [
        {"status": ["success"]},
        {"status": {"a": 1}},
        {"results": {"scores": 5}},
        {"results": {"scores": True}},
        {"results": {"scores": "abc"}},
    ],
)
def test_a_malformed_log_does_not_stop_the_other_files(
    tmp_path: Path, hostile: dict[str, Any]
) -> None:
    """Content detection runs on every JSON file; a bad one must not abort the run."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts / "bad.json", {**_log(), **hostile})
    _write(artifacts / "good.json", _log())

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    good = [
        e for e in report.evidence if e.raw and (e.raw.artifact_path or "").endswith("good.json")
    ]
    assert len(good) == 1
