"""SARIF 2.1.0 parser.

Reads a SARIF file and emits a format-agnostic `ParsedSarif` summary that
normalizers can consume. The parser stays minimal on purpose: it does not
interpret tool-specific taxonomies, only counts and surfaces enough
metadata to build a NormalizedEvidence record.
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

_SEVERITY_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


@dataclass
class ParsedSarif:
    artifact: ParsedArtifact
    tool_name: str
    tool_version: str | None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _normalize_severity(raw_level: str | None) -> str:
    if raw_level is None:
        return "medium"
    return _SEVERITY_MAP.get(raw_level.lower(), "medium")


def parse_sarif(path: str | Path) -> ParsedSarif:
    resolved = ensure_file(path)
    data = load_json(resolved)

    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ParseError(f"SARIF file {resolved} has no runs")

    first_run = runs[0]
    if not isinstance(first_run, dict):
        raise ParseError(f"SARIF file {resolved} has a malformed first run")

    tool = first_run.get("tool", {})
    driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
    tool_name = str(driver.get("name") or "unknown-sarif-tool")
    tool_version_raw = driver.get("version") or driver.get("semanticVersion")
    tool_version = str(tool_version_raw) if tool_version_raw else None

    findings_count: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    total = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if not isinstance(result, dict):
                continue
            total += 1
            level = result.get("level")
            severity_bucket = _normalize_severity(level if isinstance(level, str) else None)
            if severity_bucket not in findings_count:
                findings_count[severity_bucket] = 0
            findings_count[severity_bucket] += 1

    artifact = describe(resolved, content_type="application/sarif+json")
    return ParsedSarif(
        artifact=artifact,
        tool_name=tool_name,
        tool_version=tool_version,
        findings_count=findings_count,
        total_findings=total,
        raw=data,
    )
