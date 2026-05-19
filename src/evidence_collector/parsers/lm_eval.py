"""lm-evaluation-harness result parser.

lm-eval-harness (https://github.com/EleutherAI/lm-evaluation-harness)
is the canonical OSS evaluator for foundation models. It emits a
JSON document with the following relevant shape::

    {
      "results": {
        "<task>": {"acc": 0.83, "perplexity": 12.4, ...},
        ...
      },
      "config": {"model": "gpt2", "num_fewshot": 0, ...},
      "versions": {"<task>": "<version>"}
    }

This parser extracts:

* model identifier (from ``config.model``)
* per-task metric values (``results[<task>]``)
* a small ``findings_count`` rollup so downstream controls can decide
  pass/fail without re-reading the raw metrics.

We do NOT interpret metric semantics (whether 0.83 acc is good or
bad). Pass/fail thresholds belong in the control catalog, not in the
parser.
"""

from __future__ import annotations

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


@dataclass
class LmEvalTaskResult:
    task: str
    metrics: dict[str, float] = field(default_factory=dict)


@dataclass
class ParsedLmEval:
    artifact: ParsedArtifact
    tool_name: str = "lm-eval-harness"
    tool_version: str | None = None
    model_id: str | None = None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_tasks: int = 0
    tasks: list[LmEvalTaskResult] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _empty_findings() -> dict[str, int]:
    # lm-eval does not emit severities. We surface ``info`` per task
    # so the bundle keeps a stable per-severity shape while the
    # actual evaluation lives in control thresholds.
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _coerce_metric(value: Any) -> float | None:
    """Turn an lm-eval metric cell into a float, or ``None`` if not numeric.

    Some lm-eval tasks emit ``"acc": "N/A"`` or string-valued metrics
    when a sub-metric was skipped. We drop those rather than crash so
    the parser surfaces the metrics that DO exist.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _extract_model_id(data: dict[str, Any]) -> str | None:
    """Resolve the model identifier across lm-eval result shapes.

    Precedence (most specific first):

    1. ``config.model_args`` ``pretrained=<id>`` — used by modern lm-eval
       runs that pass the model via ``--model hf --model_args pretrained=<id>``.
       The ``pretrained`` token carries the actual model identifier.
    2. ``config.model`` — used when lm-eval was invoked with the model
       identifier directly (older runs or non-hf backends).
    3. ``model_name`` at top level — fallback for hand-shaped reports.
    """
    config = data.get("config")
    if isinstance(config, dict):
        model_args = config.get("model_args")
        if isinstance(model_args, str):
            for kv in model_args.split(","):
                if "=" in kv:
                    key, value = kv.split("=", 1)
                    if key.strip() == "pretrained" and value.strip():
                        return value.strip()
        model = config.get("model")
        if isinstance(model, str) and model:
            return model
    model_name = data.get("model_name")
    if isinstance(model_name, str) and model_name:
        return model_name
    return None


def _extract_tasks(data: dict[str, Any]) -> list[LmEvalTaskResult]:
    results = data.get("results")
    if not isinstance(results, dict):
        return []
    out: list[LmEvalTaskResult] = []
    for task_name in sorted(results.keys()):
        metrics_raw = results[task_name]
        if not isinstance(metrics_raw, dict):
            continue
        metrics: dict[str, float] = {}
        for metric_name, metric_value in metrics_raw.items():
            coerced = _coerce_metric(metric_value)
            if coerced is not None:
                metrics[metric_name] = coerced
        out.append(LmEvalTaskResult(task=task_name, metrics=metrics))
    return out


def parse_lm_eval(path: str | Path) -> ParsedLmEval:
    resolved = ensure_file(path)
    data = load_json(resolved)

    if not isinstance(data.get("results"), dict):
        raise ParseError(f"lm-eval report {resolved} has no top-level ``results`` mapping")

    tool_version = None
    versions = data.get("versions")
    if isinstance(versions, dict):
        # When versions is a flat str (single task) lm-eval embeds the
        # harness version under ``versions.lm_eval`` in newer builds.
        raw_version = versions.get("lm_eval") if isinstance(versions, dict) else None
        if isinstance(raw_version, str):
            tool_version = raw_version
    model_id = _extract_model_id(data)
    tasks = _extract_tasks(data)

    findings = _empty_findings()
    findings["info"] = len(tasks)

    artifact = describe(resolved, content_type="application/json")
    return ParsedLmEval(
        artifact=artifact,
        tool_name="lm-eval-harness",
        tool_version=tool_version,
        model_id=model_id,
        findings_count=findings,
        total_tasks=len(tasks),
        tasks=tasks,
        raw=data,
    )
