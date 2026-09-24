"""promptfoo eval output parser (``promptfoo eval -o results.json``).

promptfoo (https://www.promptfoo.dev) publishes no formal schema for its
output, so this parser reads only what its documentation states and pins
the version it was written against. The envelope looks like::

    {
      "evalId": "...",
      "results": {
        "version": 3,
        "timestamp": "...",
        "stats": {"successes": 10, "failures": 1, "errors": 0, ...},
        "results": [
          {"success": true, "score": 1.0,
           "gradingResult": {"pass": true, "componentResults": [
               {"pass": true, "assertion": {"type": "contains"}}]}},
          {"success": false, "error": "..."}
        ]
      },
      "config": {...}
    }

Only ``results.version == 3`` is read. ``gradingResult`` and its
``componentResults`` may be missing on error rows or rows without
assertions, and are skipped there. Test counts come from ``stats``; the
per-assertion tally and the failing assertion types come from the rows.

Spec reference: https://www.promptfoo.dev/docs/configuration/outputs/
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

SUPPORTED_OUTPUT_VERSION = 3


@dataclass
class ParsedPromptfoo:
    artifact: ParsedArtifact
    eval_id: str | None
    successes: int
    failures: int
    errors: int
    rows: int
    assertions_passed: int = 0
    assertions_failed: int = 0
    failed_assertion_types: dict[str, int] = field(default_factory=dict)


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def looks_like_promptfoo_output(data: Any) -> bool:
    """Whether ``data`` has the envelope of a promptfoo eval output file."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        return False
    inner = data["results"]
    stats = inner.get("stats")
    return (
        isinstance(inner.get("version"), int)
        and isinstance(inner.get("results"), list)
        and isinstance(stats, dict)
        and all(_count(stats.get(key)) is not None for key in ("successes", "failures"))
    )


def parse_promptfoo(path: str | Path) -> ParsedPromptfoo:
    resolved = ensure_file(path)
    data = load_json(resolved)
    if not looks_like_promptfoo_output(data):
        raise ParseError(
            f"{resolved} is not promptfoo eval output: expected results.version, "
            "results.stats.successes/failures and a results.results list."
        )
    inner = data["results"]
    if inner["version"] != SUPPORTED_OUTPUT_VERSION:
        raise ParseError(
            f"{resolved} is promptfoo output of version {inner['version']}; "
            f"only version {SUPPORTED_OUTPUT_VERSION} is supported."
        )
    stats = inner["stats"]
    passed = failed = 0
    failed_types: dict[str, int] = {}
    rows = inner["results"]
    for row in rows:
        grading = row.get("gradingResult") if isinstance(row, dict) else None
        components = grading.get("componentResults") if isinstance(grading, dict) else None
        for component in components or []:
            if not isinstance(component, dict) or not isinstance(component.get("pass"), bool):
                continue
            if component["pass"]:
                passed += 1
                continue
            failed += 1
            assertion = component.get("assertion")
            kind = assertion.get("type") if isinstance(assertion, dict) else None
            label = str(kind)[:100] if kind else "unknown"
            failed_types[label] = failed_types.get(label, 0) + 1
    eval_id = data.get("evalId")
    return ParsedPromptfoo(
        artifact=describe(resolved, content_type="application/json"),
        eval_id=str(eval_id)[:200] if isinstance(eval_id, str) and eval_id else None,
        successes=stats["successes"],
        failures=stats["failures"],
        errors=_count(stats.get("errors")) or 0,
        rows=len(rows),
        assertions_passed=passed,
        assertions_failed=failed,
        failed_assertion_types=failed_types,
    )
