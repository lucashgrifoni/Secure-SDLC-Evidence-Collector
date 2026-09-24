"""OSV / OSV-Scanner native JSON parser.

OSV (https://ossf.github.io/osv-schema/) is the lingua franca OSS
vulnerability format used by GHSA, PyPA, RustSec, Cargo, and others.
OSV-Scanner (https://google.github.io/osv-scanner/) wraps the schema
in a top-level ``results[*]`` envelope keyed by source (lockfile,
sbom, container).

This parser handles both shapes:

* **OSV-Scanner output** — a JSON object with a ``results`` array,
  where each result has ``packages[*].vulnerabilities[*]`` (one OSV
  record per vulnerability) plus ``packages[*].groups[*]`` summarising
  group-level severity.
* **Single OSV record** — a flat OSV vulnerability document with ``id``
  and ``affected[*]`` at the top level. Common when GHSA or PyPA
  records are saved directly as evidence.

The parser stays minimal: it counts findings by severity bucket,
extracts CVE aliases for the EPSS/KEV enrichment lane, and lists the
distinct ecosystems touched. Tool identification is done by the
``ParsedOsv.tool_name`` field which defaults to ``osv-scanner`` for
the wrapped shape and ``osv`` for the single-record shape.
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

_CVE_PATTERN = re.compile(r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b", re.IGNORECASE)


@dataclass
class ParsedOsv:
    artifact: ParsedArtifact
    tool_name: str
    tool_version: str | None = None
    findings_count: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    cve_ids: list[str] = field(default_factory=list)
    ecosystems: list[str] = field(default_factory=list)
    package_count: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _empty_findings() -> dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}


def _severity_bucket_from_cvss(score: float) -> str:
    """Map a CVSS base score to one of the canonical buckets.

    The thresholds match CVSS v3.1 qualitative severity ratings
    (https://www.first.org/cvss/v3.1/specification-document §5).
    """
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# CVSS v3.1 base metric weights (FIRST specification, section 7.4).
_CVSS3_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR: dict[str, dict[str, float]] = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}
_QUALITATIVE_BUCKETS: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _cvss3_roundup(value: float) -> float:
    """The specification's Roundup, done in integers to avoid float drift."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (scaled // 10_000 + 1) / 10.0


def _cvss3_base_score(vector: str) -> float | None:
    """Compute the base score of a CVSS v3.0 or v3.1 vector.

    Both versions share the base equations. Only the eight base metrics are
    read; temporal and environmental metrics do not change the base score. A
    vector missing any base metric, or carrying a value the specification
    does not define, returns ``None`` rather than a guess.
    """
    head, _, body = vector.partition("/")
    if head not in {"CVSS:3.0", "CVSS:3.1"}:
        return None
    metrics = dict(part.split(":", 1) for part in body.split("/") if ":" in part)
    try:
        scope = metrics["S"]
        weights = {name: table[metrics[name]] for name, table in _CVSS3_WEIGHTS.items()}
        privileges = _CVSS3_PR[scope][metrics["PR"]]
    except KeyError:
        return None
    impact_sub = 1 - (1 - weights["C"]) * (1 - weights["I"]) * (1 - weights["A"])
    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges * weights["UI"]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _cvss3_roundup(min(impact + exploitability, 10.0))
    return _cvss3_roundup(min(1.08 * (impact + exploitability), 10.0))


def _extract_cvss_score(severity_entry: Any) -> float | None:
    """Pull a numeric CVSS base score from an OSV ``severity[*]`` entry.

    OSV severity entries are ``{"type": "CVSS_V3" | "CVSS_V4", "score":
    "CVSS:3.1/AV:N/AC:L/..."}``. A v3.0 or v3.1 vector is scored with the
    specification's base equations. A bare number (``"7.5"``) is still
    accepted. A v4.0 vector is not scored here, because its score comes from
    the specification's lookup table rather than a formula; the caller falls
    back to the advisory's own rating or to ``medium``.
    """
    if not isinstance(severity_entry, dict):
        return None
    score_raw = severity_entry.get("score")
    if not isinstance(score_raw, str):
        return None
    score_raw = score_raw.strip()
    # Plain numeric score, e.g. "7.5".
    try:
        return float(score_raw)
    except ValueError:
        pass
    if score_raw.startswith("CVSS:3."):
        return _cvss3_base_score(score_raw)
    # Anything else: extract a trailing numeric component when present.
    match = re.search(r"/([0-9](?:\.[0-9]+)?)\b", score_raw)
    if match is not None:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _bucket_for_vulnerability(vuln: dict[str, Any]) -> str:
    """Return the severity bucket for a single OSV vulnerability.

    Picks the highest CVSS score across the ``severity[*]`` entries
    that we can parse. Without one, the advisory's own qualitative rating
    (``database_specific.severity``, which GitHub advisories carry) is used,
    and only then ``medium``, so an unrated finding still flows into the
    verdict.
    """
    severities = vuln.get("severity")
    best: float | None = None
    for entry in severities if isinstance(severities, list) else []:
        score = _extract_cvss_score(entry)
        if score is None:
            continue
        if best is None or score > best:
            best = score
    if best is not None:
        return _severity_bucket_from_cvss(best)
    specific = vuln.get("database_specific")
    rating = specific.get("severity") if isinstance(specific, dict) else None
    if isinstance(rating, str) and rating.strip().upper() in _QUALITATIVE_BUCKETS:
        return _QUALITATIVE_BUCKETS[rating.strip().upper()]
    return "medium"


def _collect_cves_from_strings(values: Any, sink: set[str]) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str):
            continue
        for match in _CVE_PATTERN.findall(value):
            sink.add(match.upper())


def _is_osv_scanner_envelope(data: dict[str, Any]) -> bool:
    return isinstance(data.get("results"), list)


def _is_single_osv_record(data: dict[str, Any]) -> bool:
    return isinstance(data.get("id"), str) and isinstance(data.get("affected"), list)


def _parse_osv_scanner_envelope(
    data: dict[str, Any],
) -> tuple[dict[str, int], int, list[str], list[str], int]:
    findings: dict[str, int] = _empty_findings()
    total = 0
    cve_ids: set[str] = set()
    ecosystems: list[str] = []
    seen_ecosystems: set[str] = set()
    package_count = 0

    for result in data["results"]:
        if not isinstance(result, dict):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if isinstance(package, dict):
                eco = package.get("ecosystem")
                if isinstance(eco, str) and eco and eco not in seen_ecosystems:
                    ecosystems.append(eco)
                    seen_ecosystems.add(eco)
            vulns = entry.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            if vulns:
                package_count += 1
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                total += 1
                findings[_bucket_for_vulnerability(vuln)] += 1
                _collect_cves_from_strings(vuln.get("aliases"), cve_ids)
                _collect_cves_from_strings([vuln.get("id")], cve_ids)
    return findings, total, sorted(cve_ids), ecosystems, package_count


def _parse_single_osv_record(
    data: dict[str, Any],
) -> tuple[dict[str, int], int, list[str], list[str], int]:
    findings: dict[str, int] = _empty_findings()
    bucket = _bucket_for_vulnerability(data)
    findings[bucket] += 1
    cve_ids: set[str] = set()
    _collect_cves_from_strings(data.get("aliases"), cve_ids)
    _collect_cves_from_strings([data.get("id")], cve_ids)
    ecosystems: list[str] = []
    seen_ecosystems: set[str] = set()
    affected = data.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            if not isinstance(package, dict):
                continue
            eco = package.get("ecosystem")
            if isinstance(eco, str) and eco and eco not in seen_ecosystems:
                ecosystems.append(eco)
                seen_ecosystems.add(eco)
    return findings, 1, sorted(cve_ids), ecosystems, 1 if affected else 0


def parse_osv(path: str | Path) -> ParsedOsv:
    resolved = ensure_file(path)
    data = load_json(resolved)

    if _is_osv_scanner_envelope(data):
        findings, total, cve_ids, ecosystems, package_count = _parse_osv_scanner_envelope(data)
        tool_name = "osv-scanner"
    elif _is_single_osv_record(data):
        findings, total, cve_ids, ecosystems, package_count = _parse_single_osv_record(data)
        tool_name = "osv"
    else:
        raise ParseError(
            f"File {resolved} is neither an OSV-Scanner envelope (results[]) "
            "nor a single OSV record (id + affected[])."
        )

    artifact = describe(resolved, content_type="application/json")
    return ParsedOsv(
        artifact=artifact,
        tool_name=tool_name,
        findings_count=findings,
        total_findings=total,
        cve_ids=cve_ids,
        ecosystems=ecosystems,
        package_count=package_count,
        raw=data,
    )
