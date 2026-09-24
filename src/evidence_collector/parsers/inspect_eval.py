"""Inspect eval log parser (UK AI Security Institute, log format version 2).

Inspect (https://inspect.aisi.org.uk) writes one log per evaluation. The
default ``.eval`` file is binary; this parser reads the JSON form, written
with ``--log-format json`` or produced by ``inspect log convert``. Top level::

    {
      "version": 2,
      "status": "success" | "error" | "cancelled" | "started",
      "eval": {"task": "...", "model": "...", ...},
      "results": {"total_samples": 250, "completed_samples": 250,
                  "scores": [{"name": "...", "metrics": {"accuracy": {"value": 0.9}}}]},
      "stats": {...}
    }

Only format version 2 is read; any other version is refused with a parse
error rather than guessed at. Metrics are flattened to ``scorer/metric``.
Like the lm-eval parser, this one does not judge the numbers: thresholds
belong in the control catalog. What it does judge is whether the run
finished, which the normalizer uses to keep a failed run from counting.

Spec reference: https://inspect.aisi.org.uk/eval-logs.html
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
    load_json,
)

SUPPORTED_LOG_VERSION = 2
EVAL_STATUSES = frozenset({"started", "success", "cancelled", "error"})


@dataclass
class ParsedInspectEval:
    artifact: ParsedArtifact
    task: str
    model: str
    status: str
    metrics: dict[str, float] = field(default_factory=dict)
    total_samples: int | None = None
    completed_samples: int | None = None


def looks_like_inspect_log(data: Any) -> bool:
    """Whether ``data`` has the top-level shape of an Inspect eval log."""
    if not isinstance(data, dict) or not isinstance(data.get("eval"), dict):
        return False
    spec = data["eval"]
    status = data.get("status")
    # Detection runs on every JSON artifact, so a hostile shape must answer
    # False, not raise: a list here is unhashable for the set lookup.
    return (
        isinstance(data.get("version"), int)
        and isinstance(status, str)
        and status in EVAL_STATUSES
        and isinstance(spec.get("task"), str)
        and isinstance(spec.get("model"), str)
    )


def _metrics(results: Any) -> dict[str, float]:
    out: dict[str, float] = {}
    if not isinstance(results, dict):
        return out
    scores = results.get("scores")
    if not isinstance(scores, list):
        return out
    for score in scores:
        if not isinstance(score, dict) or not isinstance(score.get("metrics"), dict):
            continue
        scorer = str(score.get("name") or "score")
        for key, metric in score["metrics"].items():
            value = metric.get("value") if isinstance(metric, dict) else None
            # bool is an int subclass, and Python's json reads NaN and Infinity;
            # neither is a metric value.
            if (
                isinstance(value, int | float)
                and not isinstance(value, bool)
                and math.isfinite(value)
            ):
                out[f"{scorer}/{metric.get('name') or key}"] = float(value)
    return out


def _count(results: Any, key: str) -> int | None:
    value = results.get(key) if isinstance(results, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def parse_inspect_eval(path: str | Path) -> ParsedInspectEval:
    resolved = ensure_file(path)
    data = load_json(resolved)
    if not looks_like_inspect_log(data):
        raise ParseError(
            f"{resolved} is not an Inspect eval log: expected version, status, "
            "eval.task and eval.model at the top level."
        )
    if data["version"] != SUPPORTED_LOG_VERSION:
        raise ParseError(
            f"{resolved} is an Inspect log of format version {data['version']}; "
            f"only version {SUPPORTED_LOG_VERSION} is supported."
        )
    results = data.get("results")
    return ParsedInspectEval(
        artifact=describe(resolved, content_type="application/json"),
        task=data["eval"]["task"],
        model=data["eval"]["model"],
        status=data["status"],
        metrics=_metrics(results),
        total_samples=_count(results, "total_samples"),
        completed_samples=_count(results, "completed_samples"),
    )
