"""Local artifact collector.

Walks configured directories and produces `NormalizedEvidence` records from
the files it recognizes. File type detection is based on extension and
content sniffing when needed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.domain.models import (
    EvidenceException,
    NormalizedEvidence,
    ReleaseContext,
)
from evidence_collector.normalizers import (
    normalize_attestation,
    normalize_junit,
    normalize_sarif,
    normalize_sbom,
    normalize_zap,
)
from evidence_collector.parsers import (
    parse_attestation,
    parse_exception,
    parse_junit,
    parse_sarif,
    parse_sbom,
    parse_zap,
)
from evidence_collector.parsers._common import ParseError

logger = logging.getLogger(__name__)


@dataclass
class LocalCollectionError:
    path: Path
    reason: str


@dataclass
class LocalCollectionReport:
    evidence: list[NormalizedEvidence] = field(default_factory=list)
    exceptions: list[EvidenceException] = field(default_factory=list)
    errors: list[LocalCollectionError] = field(default_factory=list)
    inspected_files: int = 0


class LocalArtifactCollector:
    """Collects evidence from filesystem directories."""

    def __init__(
        self,
        release: ReleaseContext,
        *,
        artifacts_dirs: list[Path] | None = None,
        attestations_dirs: list[Path] | None = None,
        exceptions_dirs: list[Path] | None = None,
        artifact_root: Path | None = None,
    ) -> None:
        self._release = release
        self._artifacts_dirs = artifacts_dirs or []
        self._attestations_dirs = attestations_dirs or []
        self._exceptions_dirs = exceptions_dirs or []
        self._artifact_root = str(artifact_root) if artifact_root else None

    def collect(self) -> LocalCollectionReport:
        report = LocalCollectionReport()
        for directory in self._artifacts_dirs:
            if not directory.exists():
                report.errors.append(
                    LocalCollectionError(path=directory, reason="directory not found")
                )
                continue
            for file_path in sorted(p for p in directory.rglob("*") if p.is_file()):
                report.inspected_files += 1
                self._ingest_artifact(file_path, report)
        for directory in self._attestations_dirs:
            if not directory.exists():
                report.errors.append(
                    LocalCollectionError(path=directory, reason="directory not found")
                )
                continue
            for file_path in sorted(p for p in directory.rglob("*") if p.is_file()):
                report.inspected_files += 1
                self._ingest_attestation(file_path, report)
        for directory in self._exceptions_dirs:
            if not directory.exists():
                report.errors.append(
                    LocalCollectionError(path=directory, reason="directory not found")
                )
                continue
            for file_path in sorted(p for p in directory.rglob("*") if p.is_file()):
                report.inspected_files += 1
                self._ingest_exception(file_path, report)
        return report

    def _ingest_exception(self, file_path: Path, report: LocalCollectionReport) -> None:
        suffix = file_path.suffix.lower()
        if suffix not in {".yaml", ".yml", ".json"}:
            return
        try:
            report.exceptions.append(parse_exception(file_path))
        except (ParseError, FileNotFoundError) as exc:
            logger.warning("Failed to ingest exception %s: %s", file_path, exc)
            report.errors.append(LocalCollectionError(path=file_path, reason=str(exc)))

    def _ingest_artifact(self, file_path: Path, report: LocalCollectionReport) -> None:
        suffix = file_path.suffix.lower()
        try:
            if suffix in {".sarif", ".sarif.json"} or _looks_like_sarif(file_path):
                parsed = parse_sarif(file_path)
                evidence = normalize_sarif(parsed, self._release, artifact_root=self._artifact_root)
                report.evidence.append(evidence)
                return
            if _looks_like_sbom(file_path):
                parsed_sbom = parse_sbom(file_path)
                report.evidence.append(
                    normalize_sbom(parsed_sbom, self._release, artifact_root=self._artifact_root)
                )
                return
            if _looks_like_zap(file_path):
                parsed_zap = parse_zap(file_path)
                report.evidence.append(
                    normalize_zap(parsed_zap, self._release, artifact_root=self._artifact_root)
                )
                return
            if suffix in {".xml"}:
                parsed_junit = parse_junit(file_path)
                report.evidence.append(
                    normalize_junit(parsed_junit, self._release, artifact_root=self._artifact_root)
                )
                return
            logger.debug("Ignoring unrecognized artifact: %s", file_path)
        except (ParseError, FileNotFoundError) as exc:
            logger.warning("Failed to ingest %s: %s", file_path, exc)
            report.errors.append(LocalCollectionError(path=file_path, reason=str(exc)))

    def _ingest_attestation(self, file_path: Path, report: LocalCollectionReport) -> None:
        suffix = file_path.suffix.lower()
        if suffix not in {".yaml", ".yml", ".json"}:
            return
        try:
            parsed = parse_attestation(file_path)
            report.evidence.append(
                normalize_attestation(parsed, self._release, artifact_root=self._artifact_root)
            )
        except (ParseError, FileNotFoundError) as exc:
            logger.warning("Failed to ingest attestation %s: %s", file_path, exc)
            report.errors.append(LocalCollectionError(path=file_path, reason=str(exc)))


def _looks_like_sarif(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    data = _peek_json(path)
    return isinstance(data, dict) and "runs" in data


def _looks_like_sbom(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    return data.get("bomFormat") == "CycloneDX" or "components" in data or "spdxVersion" in data


def _looks_like_zap(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    site = data.get("site")
    if not isinstance(site, list) or not site:
        return False
    first = site[0]
    return isinstance(first, dict) and ("alerts" in first or "@name" in first)


def _peek_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None
