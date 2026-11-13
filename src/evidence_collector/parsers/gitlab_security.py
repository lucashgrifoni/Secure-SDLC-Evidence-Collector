"""GitLab Security Report parser (report schema 15.x).

GitLab's own analyzers write their results as JSON security reports, the
files a GitLab job declares under ``artifacts:reports``. GitLab types a
report by its ``scan.type`` field, not by its file name, so this parser does
the same::

    sast                -> sast_scan
    secret_detection    -> secrets_scan
    dependency_scanning -> sca_scan
    container_scanning  -> sca_scan
    dast                -> dast_scan

Container scanning maps to ``sca_scan`` because that is what the collector
already does with the same findings from Trivy (``os-pkgs`` results): they
are vulnerable packages, and the collector has no separate container type.

Each report is one scan, so it yields one evidence. Unlike Trivy, a report
with no vulnerabilities is still a claim the scanner made: ``scan.type``
names the scan that ran, so an empty list means that scan found nothing.

Only schema major 15 and the five scan types above are claimed. Reports of
other types (API fuzzing, coverage fuzzing) or another schema major are left
to the "matched no parser" list, as they were before this parser existed:
no capture of them was available to check the reading against.
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

SUPPORTED_SCHEMA_MAJOR = "15"

SUPPORTED_SCAN_TYPES = frozenset(
    {"sast", "secret_detection", "dependency_scanning", "container_scanning", "dast"}
)

# The schema's severity enum, lower-cased: Info, Unknown, Low, Medium, High,
# Critical. Another word is counted as unknown rather than dropped.
_SEVERITY_BUCKETS = frozenset({"critical", "high", "medium", "low", "info", "unknown"})

SCAN_STATUS_FAILURE = "failure"


@dataclass
class ParsedGitLabSecurityReport:
    artifact: ParsedArtifact
    report_version: str
    scan_type: str
    scan_status: str | None
    analyzer_id: str | None
    analyzer_version: str | None
    scanner_id: str
    scanner_version: str | None
    findings_count: dict[str, int] = field(default_factory=dict)
    cve_ids: list[str] = field(default_factory=list)
    image: str | None = None

    @property
    def total_findings(self) -> int:
        return sum(self.findings_count.values())

    @property
    def scan_failed(self) -> bool:
        return self.scan_status == SCAN_STATUS_FAILURE


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _section(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def looks_like_gitlab_security_report(data: Any) -> bool:
    """True when ``data`` is a schema-15 report of a supported scan type.

    Takes parsed data so the collector can feed it from its memoized JSON
    peek instead of reading the file again.
    """
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        return False
    version = _optional_str(data.get("version"))
    if version is None or version.split(".", 1)[0] != SUPPORTED_SCHEMA_MAJOR:
        return False
    scan_type = _section(data, "scan").get("type")
    return isinstance(scan_type, str) and scan_type in SUPPORTED_SCAN_TYPES


def _bucket(value: Any) -> str:
    severity = _optional_str(value)
    if severity is None:
        return "unknown"
    lowered = severity.lower()
    return lowered if lowered in _SEVERITY_BUCKETS else "unknown"


def _cve_ids(vulnerability: dict[str, Any]) -> list[str]:
    """CVE ids from the identifiers typed ``cve``.

    The top-level ``cve`` field is not one: in a SAST report it holds a
    location key such as ``semgrep_id:bandit.B307:14:14``.
    """
    identifiers = vulnerability.get("identifiers")
    found: list[str] = []
    for identifier in identifiers if isinstance(identifiers, list) else []:
        if not isinstance(identifier, dict):
            continue
        kind = _optional_str(identifier.get("type"))
        value = _optional_str(identifier.get("value"))
        if kind is not None and kind.lower() == "cve" and value is not None:
            found.append(value)
    return found


def _image(vulnerability: dict[str, Any]) -> str | None:
    return _optional_str(_section(vulnerability, "location").get("image"))


def parse_gitlab_security_report(path: str | Path) -> ParsedGitLabSecurityReport:
    resolved = ensure_file(path)
    data = load_json(resolved)
    if not looks_like_gitlab_security_report(data):
        raise ParseError(
            f"File {resolved} is not a GitLab Security Report this collector reads "
            f"(expected schema {SUPPORTED_SCHEMA_MAJOR}.x, a 'vulnerabilities' array and "
            f"scan.type one of {', '.join(sorted(SUPPORTED_SCAN_TYPES))})."
        )

    scan = _section(data, "scan")
    analyzer = _section(scan, "analyzer")
    scanner = _section(scan, "scanner")
    findings_count: dict[str, int] = {}
    cve_ids: list[str] = []
    image: str | None = None
    for vulnerability in data["vulnerabilities"]:
        if not isinstance(vulnerability, dict):
            continue
        bucket = _bucket(vulnerability.get("severity"))
        findings_count[bucket] = findings_count.get(bucket, 0) + 1
        for cve_id in _cve_ids(vulnerability):
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)
        image = image or _image(vulnerability)

    analyzer_id = _optional_str(analyzer.get("id"))
    return ParsedGitLabSecurityReport(
        artifact=describe(resolved, content_type="application/json"),
        report_version=data["version"],
        scan_type=scan["type"],
        scan_status=_optional_str(scan.get("status")),
        analyzer_id=analyzer_id,
        analyzer_version=_optional_str(analyzer.get("version")),
        scanner_id=_optional_str(scanner.get("id")) or analyzer_id or "gitlab-analyzer",
        scanner_version=_optional_str(scanner.get("version")),
        findings_count=findings_count,
        cve_ids=cve_ids,
        image=image,
    )
