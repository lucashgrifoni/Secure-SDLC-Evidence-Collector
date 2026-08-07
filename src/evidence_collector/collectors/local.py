"""Local artifact collector.

Walks configured directories and produces `NormalizedEvidence` records from
the files it recognizes. File type detection is based on extension and
content sniffing when needed.
"""

from __future__ import annotations

import codecs
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
    normalize_garak,
    normalize_junit,
    normalize_lm_eval,
    normalize_model_card,
    normalize_osv,
    normalize_provenance,
    normalize_release_attestation,
    normalize_sarif,
    normalize_sbom,
    normalize_vsa,
    normalize_zap,
)
from evidence_collector.parsers import (
    parse_attestation,
    parse_exception,
    parse_garak,
    parse_junit,
    parse_lm_eval,
    parse_model_card,
    parse_osv,
    parse_provenance,
    parse_release_attestation,
    parse_sarif,
    parse_sbom,
    parse_vsa,
    parse_zap,
)
from evidence_collector.parsers._common import MAX_INPUT_BYTES, ParseError
from evidence_collector.parsers.intoto_provenance import file_has_provenance
from evidence_collector.parsers.intoto_vsa import VSA_PREDICATE_TYPE
from evidence_collector.parsers.release_attestation import file_has_release_attestation
from evidence_collector.parsers.sbom import is_spdx3

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

    def _usable_directory(self, directory: Path, report: LocalCollectionReport) -> bool:
        """Return whether ``directory`` can be walked, recording why when it cannot.

        The check used to be ``not directory.exists()``, which a *file* passes:
        ``Path.rglob`` over a file yields nothing, so the run reported zero
        evidence with no warning at all. The realistic trigger is a shell glob —
        ``--artifacts-dir artifacts/*.sarif`` expands to a file — and the result
        is a report claiming the SAST/SCA/secrets evidence is missing while the
        scanners actually ran. A false negative that looks exactly like a real
        finding is worse than an error, so the two cases are now distinct.
        """
        if not directory.exists():
            report.errors.append(LocalCollectionError(path=directory, reason="directory not found"))
            return False
        if not directory.is_dir():
            report.errors.append(
                LocalCollectionError(
                    path=directory,
                    reason="not a directory (expected a folder; pass the containing folder, "
                    "not a single file)",
                )
            )
            return False
        return True

    def collect(self) -> LocalCollectionReport:
        report = LocalCollectionReport()
        for directory in self._artifacts_dirs:
            if not self._usable_directory(directory, report):
                continue
            for file_path in sorted(p for p in directory.rglob("*") if p.is_file()):
                report.inspected_files += 1
                self._ingest_artifact(file_path, report)
        for directory in self._attestations_dirs:
            if not self._usable_directory(directory, report):
                continue
            for file_path in sorted(p for p in directory.rglob("*") if p.is_file()):
                report.inspected_files += 1
                self._ingest_attestation(file_path, report)
        for directory in self._exceptions_dirs:
            if not self._usable_directory(directory, report):
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
        except (ParseError, OSError) as exc:
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
            # in-toto SLSA VSA detection runs before SBOM/OSV: a VSA is a
            # JSON Statement keyed by its ``predicateType``, with none of the
            # SBOM/OSV discriminators, so the explicit predicate check is the
            # safe, unambiguous detector.
            if _looks_like_vsa(file_path):
                parsed_vsa = parse_vsa(file_path)
                report.evidence.append(
                    normalize_vsa(parsed_vsa, self._release, artifact_root=self._artifact_root)
                )
                return
            # in-toto attestations beyond the VSA: SLSA build provenance
            # (incl. GitHub Artifact Attestations) and the release predicate.
            # Both arrive as a raw Statement, a DSSE envelope, or a Sigstore
            # bundle, and detection is by the unwrapped predicateType.
            #
            # A single file — notably the JSONL that `gh attestation download`
            # writes — can carry BOTH predicates. Each detector is therefore
            # offered the file independently and both evidences are appended;
            # returning on the first match would silently drop the other.
            intoto_found = False
            if _looks_like_provenance(file_path):
                parsed_prov = parse_provenance(file_path)
                report.evidence.append(
                    normalize_provenance(
                        parsed_prov, self._release, artifact_root=self._artifact_root
                    )
                )
                intoto_found = True
            if _looks_like_release_attestation(file_path):
                parsed_rel = parse_release_attestation(file_path)
                report.evidence.append(
                    normalize_release_attestation(
                        parsed_rel, self._release, artifact_root=self._artifact_root
                    )
                )
                intoto_found = True
            if intoto_found:
                return
            if _looks_like_sbom(file_path):
                parsed_sbom = parse_sbom(file_path)
                report.evidence.append(
                    normalize_sbom(parsed_sbom, self._release, artifact_root=self._artifact_root)
                )
                return
            # OSV detection must come after SBOM detection so we do not
            # mis-classify a CycloneDX with an embedded ``vulnerabilities``
            # block as an OSV report.
            if _looks_like_osv(file_path):
                parsed_osv = parse_osv(file_path)
                report.evidence.append(
                    normalize_osv(parsed_osv, self._release, artifact_root=self._artifact_root)
                )
                return
            # T6.5 AI evidence detection. Filename-based first because
            # garak / lm-eval / model-card payloads are JSON shapes we
            # do not want to confuse with generic JSON artifacts.
            if _looks_like_garak(file_path):
                parsed_garak = parse_garak(file_path)
                report.evidence.append(
                    normalize_garak(parsed_garak, self._release, artifact_root=self._artifact_root)
                )
                return
            if _looks_like_lm_eval(file_path):
                parsed_lm = parse_lm_eval(file_path)
                report.evidence.append(
                    normalize_lm_eval(parsed_lm, self._release, artifact_root=self._artifact_root)
                )
                return
            if _looks_like_model_card(file_path):
                parsed_mc = parse_model_card(file_path)
                report.evidence.append(
                    normalize_model_card(
                        parsed_mc, self._release, artifact_root=self._artifact_root
                    )
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
            # Nothing claimed the file. Before dropping it, separate "a format
            # we do not recognize" from "a file we could not even read": the
            # latter is evidence the caller believes they supplied, so losing
            # it silently would understate coverage with no way to notice.
            encoding_error = _undecodable_text_reason(file_path)
            if encoding_error is not None:
                logger.warning("Failed to ingest %s: %s", file_path, encoding_error)
                report.errors.append(LocalCollectionError(path=file_path, reason=encoding_error))
                return
            logger.debug("Ignoring unrecognized artifact: %s", file_path)
        except (ParseError, OSError) as exc:
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
        except (ParseError, OSError) as exc:
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
    return (
        data.get("bomFormat") == "CycloneDX"
        or "components" in data
        or "spdxVersion" in data
        or is_spdx3(data)
    )


def _looks_like_vsa(path: Path) -> bool:
    """Detect a raw in-toto Statement carrying the SLSA VSA predicate.

    The ``predicateType`` is the unambiguous marker; DSSE-wrapped /
    signed envelopes are out of scope for this detector (the payload is
    base64-encoded) and should be decoded upstream.
    """
    if path.suffix.lower() != ".json":
        return False
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    return data.get("predicateType") == VSA_PREDICATE_TYPE


def _looks_like_provenance(path: Path) -> bool:
    """Detect SLSA build provenance in a raw in-toto Statement, a DSSE
    envelope, or a Sigstore bundle — including any record of a ``.jsonl`` such
    as ``gh attestation download`` writes (which may bundle several
    predicates)."""
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return False
    return file_has_provenance(path)


def _looks_like_release_attestation(path: Path) -> bool:
    """Detect an in-toto release attestation in a raw Statement, a DSSE
    envelope, or a Sigstore bundle — including any record of a ``.jsonl``
    such as ``gh attestation download`` writes."""
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return False
    return file_has_release_attestation(path)


def _looks_like_garak(path: Path) -> bool:
    """Detect a garak report by filename.

    garak emits ``*.report.jsonl`` or ``*.garak.json``; the JSONL
    inside is line-delimited and we cannot peek with ``json.load``,
    so the filename heuristic is the cleanest detector. We also
    accept ``garak.json`` as a default name.
    """
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix not in {".json", ".jsonl"}:
        return False
    return (
        name.endswith(".garak.json")
        or name.endswith(".garak.jsonl")
        or name == "garak.json"
        or name == "garak.jsonl"
        or name.endswith(".report.jsonl")
    )


def _looks_like_lm_eval(path: Path) -> bool:
    """Detect an lm-evaluation-harness JSON result by filename + shape."""
    if path.suffix.lower() != ".json":
        return False
    name = path.name.lower()
    if name.endswith(".lm-eval.json") or name.endswith(".lm_eval.json") or name == "lm-eval.json":
        return True
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    # Top-level ``results`` mapping + ``versions`` is lm-eval's
    # standard shape across versions.
    return isinstance(data.get("results"), dict) and isinstance(data.get("versions"), dict)


def _looks_like_model_card(path: Path) -> bool:
    """Detect a model card JSON by filename + discriminating keys."""
    if path.suffix.lower() != ".json":
        return False
    name = path.name.lower()
    if name in {"model-card.json", "model_card.json"} or name.endswith(".modelcard.json"):
        return True
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    return isinstance(data.get("model_details"), dict) or isinstance(data.get("model-index"), list)


def _looks_like_osv(path: Path) -> bool:
    """Detect OSV-Scanner native output or a single OSV record.

    OSV-Scanner emits ``{"results": [...]}`` and a single OSV record
    carries ``{"id": "...", "affected": [...]}`` at the top level. We
    avoid matching on filename only because OSV-Scanner is often run
    with ``--format json --output osv.json`` but other tools also use
    that filename.
    """
    if path.suffix.lower() != ".json":
        return False
    data = _peek_json(path)
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("results"), list):
        return True
    return isinstance(data.get("id"), str) and isinstance(data.get("affected"), list)


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


# Suffixes the collector treats as text evidence. A file with one of these
# that cannot be decoded as UTF-8 is a reporting problem worth surfacing; a
# stray binary with another suffix is not.
_TEXT_EVIDENCE_SUFFIXES = frozenset({".json", ".jsonl", ".sarif", ".xml", ".yaml", ".yml"})

# Enough bytes to catch a wrong-encoding file (a UTF-16 BOM is in the first
# two) without reading a large artifact twice.
_ENCODING_PROBE_BYTES = 8192


def _undecodable_text_reason(path: Path) -> str | None:
    """Return why ``path`` is unreadable as UTF-8 text, or ``None`` if it is fine.

    Only applies to suffixes the collector treats as text evidence. Uses an
    incremental decoder over a prefix so a multi-byte character straddling the
    probe boundary is not mistaken for corruption.
    """
    if path.suffix.lower() not in _TEXT_EVIDENCE_SUFFIXES:
        return None
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(_ENCODING_PROBE_BYTES)
    except OSError as exc:
        return f"Could not read {path}: {exc}"
    # Detection skips files over the cap without parsing them, so an oversized
    # artifact would otherwise fall through to "unrecognized" and vanish. It is
    # evidence the caller believes they supplied — say why it was not read.
    if size > MAX_INPUT_BYTES:
        return f"File {path} is {size} bytes, exceeding the {MAX_INPUT_BYTES} byte safety cap."
    decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        decoder.decode(head, False)
    except UnicodeDecodeError as exc:
        return f"Invalid text encoding in {path}: {exc}"
    return None


# Detection chains up to seven ``_peek_json`` calls over the same file before a
# parser claims it, so the document is remembered between them. A single slot is
# enough and is the reason it is not an unbounded dict: every call for one file
# happens inside one ``_ingest_artifact``, so the next file simply evicts the
# previous one and at most one parsed document is ever held.
_LAST_PEEK: dict[str, Any] = {"key": None, "value": None}


def _peek_key(path: Path) -> tuple[str, int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (str(path), stat.st_mtime_ns, stat.st_size)


def _peek_json(path: Path) -> Any:
    """Parse ``path`` for *detection* only, memoizing the most recent file.

    Never raises: an unreadable or undecodable file is simply "not this
    format", and the parser that eventually claims it reports the real reason
    via ParseError.

    The size cap is enforced here as well as in ``ensure_file``. It used to
    live only inside the parsers, which run *after* detection — so a 40 MB JSON
    was fully deserialized seven times (peak heap measured at 2.4x the file
    size) before ``ensure_file`` rejected it for exceeding the 25 MB cap that
    SECURITY.md advertises as the input guardrail.
    """
    key = _peek_key(path)
    if key is None:
        return None
    if _LAST_PEEK["key"] == key:
        return _LAST_PEEK["value"]

    value: Any = None
    if key[2] <= MAX_INPUT_BYTES:
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            value = None
    _LAST_PEEK["key"] = key
    _LAST_PEEK["value"] = value
    return value
