"""Native Trivy JSON parser (SchemaVersion 2).

Trivy can already be ingested through the SARIF route, but SARIF flattens
the whole run into one document and the collector classifies it as a
single evidence type. A Trivy scan is rarely one thing: a single run over
a repository typically produces dependency vulnerabilities, secret hits
and IaC misconfigurations at once, and collapsing them means a Terraform
misconfiguration ends up indistinguishable from a code vulnerability.

The native JSON keeps them apart. ``Results[].Class`` names what each
result block is, and this parser maps that to the collector's evidence
types::

    os-pkgs, lang-pkgs  -> sca_scan
    secret              -> secrets_scan
    config              -> iac_scan

One report therefore yields up to **three** evidences. ``license``,
``license-file``, ``custom`` and ``unknown`` classes are read past: the
collector has no evidence type whose meaning matches them, and inventing
one would be worse than declining.

The class values above are the literal ``ResultClass`` constants from
Trivy's own ``pkg/types/report.go``. Note ``config`` — not
"misconfiguration", which is what the format is usually called in prose.

``Metadata.RepoDigests`` / ``Metadata.ImageID`` become the subject digest
when the scan targeted an image, so container findings attach to what was
actually scanned rather than to the release id.

**SchemaVersion is pinned to 2.** Trivy publishes no JSON Schema for this
format (aquasecurity/trivy discussion #7552), so the version field is the
only compatibility signal there is. A different version fails with a
diagnostic instead of being parsed under version-2 assumptions.
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

SUPPORTED_SCHEMA_VERSION = 2

# Literal ResultClass values from Trivy's pkg/types/report.go.
CLASS_OS_PKG = "os-pkgs"
CLASS_LANG_PKG = "lang-pkgs"
CLASS_CONFIG = "config"
# S105 is suppressed below because it matches on the variable *name*:
# this is Trivy's ResultClass for the secret **scanner**, not a credential.
CLASS_SECRET = "secret"  # noqa: S105

# Classes the collector deliberately does not map. Kept explicit so a
# reader can see they were considered rather than forgotten.
UNMAPPED_CLASSES = frozenset({"license", "license-file", "custom", "unknown"})

_SEVERITY_BUCKETS = frozenset({"critical", "high", "medium", "low", "unknown"})


@dataclass
class TrivyResultGroup:
    """One evidence-worth of Trivy findings, already bucketed by class."""

    kind: str
    findings_count: dict[str, int] = field(default_factory=dict)
    ids: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(self.findings_count.values())


@dataclass
class ParsedTrivyJson:
    artifact: ParsedArtifact
    schema_version: int
    groups: list[TrivyResultGroup] = field(default_factory=list)
    artifact_name: str | None = None
    artifact_type: str | None = None
    image_id: str | None = None
    repo_digest: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _bucket(value: Any) -> str:
    """Map a Trivy severity to a findings bucket.

    Trivy emits CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN. Anything else is counted
    as ``unknown`` rather than dropped: a finding that exists must show up
    in the count even when its severity word is unfamiliar.
    """
    severity = _optional_str(value)
    if severity is None:
        return "unknown"
    lowered = severity.lower()
    return lowered if lowered in _SEVERITY_BUCKETS else "unknown"


def _is_failing_misconfiguration(entry: dict[str, Any]) -> bool:
    """True unless Trivy explicitly recorded this check as passing.

    With ``--include-non-failures`` a report carries passed checks too.
    Counting those as findings would invent misconfigurations out of
    controls that are actually satisfied.
    """
    return _optional_str(entry.get("Status")) != "PASS"


def looks_like_trivy_json(data: Any) -> bool:
    """True when ``data`` is a native Trivy JSON report.

    Takes parsed data so the collector can feed it from the memoized JSON
    peek rather than reading the file a second time.
    """
    if not isinstance(data, dict):
        return False
    return "SchemaVersion" in data and isinstance(data.get("Results"), list)


def _repo_digest(metadata: dict[str, Any]) -> str | None:
    digests = metadata.get("RepoDigests")
    if isinstance(digests, list):
        for digest in digests:
            value = _optional_str(digest)
            if value is not None:
                return value
    return None


def _collect(
    result: dict[str, Any],
    key: str,
    id_field: str,
    group: TrivyResultGroup,
    *,
    only_failing: bool = False,
) -> None:
    entries = result.get(key)
    if not isinstance(entries, list):
        return
    target = _optional_str(result.get("Target"))
    counted = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if only_failing and not _is_failing_misconfiguration(entry):
            continue
        bucket = _bucket(entry.get("Severity"))
        group.findings_count[bucket] = group.findings_count.get(bucket, 0) + 1
        identifier = _optional_str(entry.get(id_field))
        if identifier is not None and identifier not in group.ids:
            group.ids.append(identifier)
        counted = True
    if counted and target is not None and target not in group.targets:
        group.targets.append(target)


def parse_trivy_json(path: str | Path) -> ParsedTrivyJson:
    resolved = ensure_file(path)
    data = load_json(resolved)

    if not looks_like_trivy_json(data):
        raise ParseError(
            f"File {resolved} is not a native Trivy JSON report "
            "(expected 'SchemaVersion' and a 'Results' array)."
        )

    schema_version = data.get("SchemaVersion")
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise ParseError(
            f"Trivy report {resolved} declares SchemaVersion "
            f"{schema_version!r}; this parser only understands "
            f"{SUPPORTED_SCHEMA_VERSION}. Trivy publishes no JSON Schema for "
            "this format, so the version field is the only compatibility "
            "signal — parsing it anyway could silently mis-read the report."
        )

    by_kind: dict[str, TrivyResultGroup] = {}

    def group_for(kind: str) -> TrivyResultGroup:
        if kind not in by_kind:
            by_kind[kind] = TrivyResultGroup(kind=kind)
        return by_kind[kind]

    results = data.get("Results")
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        result_class = _optional_str(result.get("Class"))
        if result_class in {CLASS_OS_PKG, CLASS_LANG_PKG}:
            _collect(result, "Vulnerabilities", "VulnerabilityID", group_for("sca"))
        elif result_class == CLASS_SECRET:
            _collect(result, "Secrets", "RuleID", group_for("secrets"))
        elif result_class == CLASS_CONFIG:
            _collect(result, "Misconfigurations", "ID", group_for("iac"), only_failing=True)

    metadata = data.get("Metadata")
    metadata = metadata if isinstance(metadata, dict) else {}

    return ParsedTrivyJson(
        artifact=describe(resolved, content_type="application/json"),
        schema_version=SUPPORTED_SCHEMA_VERSION,
        groups=[by_kind[kind] for kind in ("sca", "secrets", "iac") if kind in by_kind],
        artifact_name=_optional_str(data.get("ArtifactName")),
        artifact_type=_optional_str(data.get("ArtifactType")),
        image_id=_optional_str(metadata.get("ImageID")),
        repo_digest=_repo_digest(metadata),
        raw=data,
    )
