"""SARIF 2.1.0 parser.

Reads a SARIF file and emits a format-agnostic `ParsedSarif` summary that
normalizers can consume. The parser stays minimal on purpose: it does not
interpret tool-specific taxonomies, only counts and surfaces enough
metadata to build a NormalizedEvidence record.

Each result is bucketed by its effective level, resolved the way SARIF
2.1.0 section 3.27.10 says: the result's own ``level``; for a result whose
``kind`` is not ``fail``, ``none``; otherwise the ``defaultConfiguration``
level of the rule it references (``ruleIndex``/``rule.index``, then
``ruleId``/``rule.id``, in the driver or in the extension named by
``rule.toolComponent``); otherwise ``warning``. A rule's numeric
``security-severity`` property can raise that bucket, never lower it.
Invocation overrides (``ruleConfigurationOverrides``) are not applied.

A result whose every suppression is ``accepted`` or carries no status is
not an open finding; it is counted in ``suppressed_count`` instead. The run
also records whether an invocation reported ``executionSuccessful: false``,
how many error-level tool notifications it carried, and whether it had no
``results`` array at all, which SARIF distinguishes from an empty one.
"""

from __future__ import annotations

import math
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
_BUCKET_RANK: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Result kinds other than "fail" (SARIF 3.27.9); their level defaults to none.
_NON_FAIL_KINDS = frozenset({"pass", "open", "informational", "notApplicable", "review"})

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
    # Results whose suppressions are all accepted: reported, not open.
    suppressed_count: int = 0
    # An invocation said ``executionSuccessful: false``.
    execution_failed: bool = False
    # Error-level tool execution or configuration notifications.
    tool_error_count: int = 0
    # The run has no ``results`` array (SARIF: unknown, not zero findings).
    results_absent: bool = False


def _normalize_severity(raw_level: str) -> str:
    return _SEVERITY_MAP.get(raw_level.lower(), "medium")


def _valid_index(value: Any, size: int) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < size:
        return value
    return None


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item if isinstance(item, dict) else {} for item in value]


def _resolve_rule(
    result: dict[str, Any], driver: dict[str, Any], extensions: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Return the rule descriptor ``result`` references, or ``None``."""
    reference = result.get("rule")
    reference = reference if isinstance(reference, dict) else {}
    component: dict[str, Any] | None = driver
    tool_component = reference.get("toolComponent")
    if isinstance(tool_component, dict):
        index = _valid_index(tool_component.get("index"), len(extensions))
        name = tool_component.get("name")
        if index is not None:
            component = extensions[index]
        elif isinstance(name, str):
            named = [c for c in [driver, *extensions] if c.get("name") == name]
            component = named[0] if len(named) == 1 else None
        else:
            component = None
    if component is None:
        return None
    rules = _dict_list(component.get("rules"))
    index = _valid_index(reference.get("index", result.get("ruleIndex")), len(rules))
    if index is not None:
        return rules[index]
    rule_id = reference.get("id", result.get("ruleId"))
    if isinstance(rule_id, str):
        for rule in rules:
            if rule.get("id") == rule_id:
                return rule
    return None


def _security_severity_bucket(rule: dict[str, Any] | None) -> str | None:
    """Bucket a rule's ``security-severity`` (0.0 to 10.0) as GitHub does."""
    properties = rule.get("properties") if rule is not None else None
    raw = properties.get("security-severity") if isinstance(properties, dict) else None
    if isinstance(raw, bool) or not isinstance(raw, (str, int, float)):
        return None
    try:
        score = float(raw)
    except ValueError:
        return None
    if not math.isfinite(score) or not 0.0 <= score <= 10.0:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0.0 else "info"


def _severity_bucket(
    result: dict[str, Any], driver: dict[str, Any], extensions: list[dict[str, Any]]
) -> str:
    """Severity bucket of one result, from its effective SARIF level."""
    level = result.get("level")
    kind = result.get("kind")
    if isinstance(kind, str) and kind in _NON_FAIL_KINDS:
        return _normalize_severity(level if isinstance(level, str) else "none")
    rule = _resolve_rule(result, driver, extensions)
    if not isinstance(level, str):
        configuration = rule.get("defaultConfiguration") if rule is not None else None
        default = configuration.get("level") if isinstance(configuration, dict) else None
        level = default if isinstance(default, str) else "warning"
    bucket = _normalize_severity(level)
    security = _security_severity_bucket(rule)
    if security is not None and _BUCKET_RANK[security] > _BUCKET_RANK[bucket]:
        return security
    return bucket


def _is_suppressed(result: dict[str, Any]) -> bool:
    """True when every suppression is accepted or has no status."""
    suppressions = result.get("suppressions")
    if not isinstance(suppressions, list) or not suppressions:
        return False
    return all(
        isinstance(item, dict) and item.get("status", "accepted") == "accepted"
        for item in suppressions
    )


def _invocation_signals(run: dict[str, Any]) -> tuple[bool, int]:
    """Whether an invocation failed, and how many error notifications it raised."""
    failed = False
    errors = 0
    for invocation in _dict_list(run.get("invocations")):
        if invocation.get("executionSuccessful") is False:
            failed = True
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            notes = _dict_list(invocation.get(key))
            errors += sum(1 for note in notes if note.get("level") == "error")
    return failed, errors


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
        if not isinstance(driver, dict):
            # A string, list or number here raised AttributeError on `.get`.
            driver = {}
        tool_name = str(driver.get("name") or "unknown-sarif-tool")
        tool_version_raw = driver.get("version") or driver.get("semanticVersion")
        extensions = _dict_list(tool.get("extensions")) if isinstance(tool, dict) else []
        execution_failed, tool_error_count = _invocation_signals(run)

        findings_count: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        total = 0
        suppressed = 0
        cve_ids: set[str] = set()
        results = run.get("results")
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            if _is_suppressed(result):
                suppressed += 1
                continue
            total += 1
            findings_count[_severity_bucket(result, driver, extensions)] += 1
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
                suppressed_count=suppressed,
                execution_failed=execution_failed,
                tool_error_count=tool_error_count,
                results_absent=not isinstance(results, list),
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
