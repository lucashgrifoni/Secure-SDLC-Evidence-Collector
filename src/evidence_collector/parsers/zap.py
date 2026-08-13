"""Parser for OWASP ZAP JSON reports.

Handles the JSON report format produced by `zap-baseline.py`,
`zap-full-scan.py`, and ZAP's built-in JSON export. The parser emits a
`ParsedZap` that normalizers turn into a `dast_scan` evidence.

The OWASP ZAP JSON document has a top-level `site` array. Each site has
an `alerts` list, and each alert has a `riskcode` (0..3 for informational
to high) and optional `confidence` and `count`. We aggregate findings by
normalized severity.
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

_RISK_CODE_TO_SEVERITY: dict[str, str] = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


@dataclass
class ParsedZap:
    artifact: ParsedArtifact
    tool_name: str
    tool_version: str | None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    target_urls: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _severity_for(alert: dict[str, Any]) -> str:
    risk_code = alert.get("riskcode")
    if risk_code is None:
        return "medium"
    return _RISK_CODE_TO_SEVERITY.get(str(risk_code), "medium")


def parse_zap(path: str | Path) -> ParsedZap:
    resolved = ensure_file(path)
    data = load_json(resolved)

    sites = data.get("site")
    if not isinstance(sites, list) or not sites:
        raise ParseError(f"ZAP report {resolved} has no `site` entries")

    generator = data.get("@generator") or data.get("generator") or "OWASP ZAP"
    version = data.get("@version") or data.get("version")

    findings_count: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    total = 0
    targets: list[str] = []

    for site in sites:
        if not isinstance(site, dict):
            continue
        target = site.get("@name") or site.get("name")
        if isinstance(target, str) and target:
            targets.append(target)
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            try:
                instance_count = max(1, int(alert.get("count", 1)))
            except (TypeError, ValueError):
                instance_count = 1
            except OverflowError:
                # `int(float("inf"))` raises OverflowError, which is neither a
                # TypeError nor a ValueError, so a non-finite `count` escaped
                # this guard and aborted the whole collection run. Python's
                # `json` accepts the bare `Infinity` and `NaN` literals, so a
                # report only has to contain one. A count that is not a finite
                # number tells us nothing about how many instances there were;
                # the alert itself is still real, so it counts as one.
                instance_count = 1
            severity = _severity_for(alert)
            findings_count[severity] = findings_count.get(severity, 0) + instance_count
            total += instance_count

    artifact = describe(resolved, content_type="application/json")
    return ParsedZap(
        artifact=artifact,
        tool_name=str(generator),
        tool_version=str(version) if version else None,
        findings_count=findings_count,
        total_findings=total,
        target_urls=targets,
        raw=data,
    )
