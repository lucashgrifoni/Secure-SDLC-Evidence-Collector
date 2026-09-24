"""SARIF 2.1.0 parser.

Reads a SARIF file and emits a format-agnostic `ParsedSarif` summary that
normalizers can consume. The parser stays minimal on purpose: it does not
interpret tool-specific taxonomies, only counts and surfaces enough
metadata to build a NormalizedEvidence record.
"""

from __future__ import annotations

import re
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

# CVE identifiers follow CVE-YYYY-NNNN+. We accept years 1999..2099 and
# 4+-digit sequence numbers because some scanners emit padded values.
_CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class ParsedSarif:
    artifact: ParsedArtifact
    tool_name: str
    tool_version: str | None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    cve_ids: list[str] = field(default_factory=list)
    # Index of the SARIF ``runs[]`` entry this record came from. A merged
    # file carries one run per tool, and each is its own evidence.
    run_index: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _normalize_severity(raw_level: str | None) -> str:
    if raw_level is None:
        return "medium"
    return _SEVERITY_MAP.get(raw_level.lower(), "medium")


def parse_sarifs(path: str | Path) -> list[ParsedSarif]:
    resolved = ensure_file(path)
    data = load_json(resolved)

    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ParseError(f"SARIF file {resolved} has no runs")

    if not isinstance(runs[0], dict):
        raise ParseError(f"SARIF file {resolved} has a malformed first run")

    artifact = describe(resolved, content_type="application/sarif+json")
    parsed: list[ParsedSarif] = []
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        tool = run.get("tool", {})
        driver = tool.get("driver", {}) if isinstance(tool, dict) else {}
        tool_name = str(driver.get("name") or "unknown-sarif-tool")
        tool_version_raw = driver.get("version") or driver.get("semanticVersion")

        findings_count: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        total = 0
        cve_ids: set[str] = set()
        results = run.get("results")
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            total += 1
            level = result.get("level")
            severity_bucket = _normalize_severity(level if isinstance(level, str) else None)
            if severity_bucket not in findings_count:
                findings_count[severity_bucket] = 0
            findings_count[severity_bucket] += 1
            _collect_cves_from_result(result, cve_ids)

        parsed.append(
            ParsedSarif(
                artifact=artifact,
                tool_name=tool_name,
                tool_version=str(tool_version_raw) if tool_version_raw else None,
                findings_count=findings_count,
                total_findings=total,
                cve_ids=sorted(cve_ids),
                run_index=index,
                raw=data,
            )
        )

    if not parsed:
        raise ParseError(f"SARIF file {resolved} has no usable runs")
    return parsed


def _candidate_strings_from_properties(properties: Any) -> list[str]:
    """Pull every plausibly CVE-bearing string out of a SARIF properties bag."""
    if not isinstance(properties, dict):
        return []
    out: list[str] = []
    tags = properties.get("tags")
    if isinstance(tags, list):
        out.extend(str(tag) for tag in tags if isinstance(tag, str))
    for key in ("cve", "cveId", "cveID"):
        value = properties.get(key)
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, list):
            out.extend(str(v) for v in value if isinstance(v, str))
    return out


def _candidate_strings_from_result(result: dict[str, Any]) -> list[str]:
    """Collect all SARIF-result strings that may contain a CVE identifier."""
    out: list[str] = []
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str):
        out.append(rule_id)
    out.extend(_candidate_strings_from_properties(result.get("properties")))
    message = result.get("message")
    if isinstance(message, dict):
        text = message.get("text")
        if isinstance(text, str):
            out.append(text)
    return out


def _collect_cves_from_result(result: dict[str, Any], sink: set[str]) -> None:
    """Mine CVE identifiers from a single SARIF result.

    Scanners encode CVEs in several places: ``ruleId`` (e.g. Trivy uses
    ``CVE-2023-1234`` as the rule id), ``properties.tags``,
    ``properties.cve`` / ``cveId``, and free-text in ``message.text``.
    ``sink`` is a set so duplicates across these sites are de-duped
    automatically.
    """
    for candidate in _candidate_strings_from_result(result):
        for match in _CVE_PATTERN.findall(candidate):
            sink.add(match.upper())


def parse_sarif(path: str | Path) -> ParsedSarif:
    """Return the first run of ``path``.

    Convenience wrapper for single-run callers and tests; the collector uses
    :func:`parse_sarifs` so a merged file does not lose every run after the
    first.
    """
    return parse_sarifs(path)[0]
