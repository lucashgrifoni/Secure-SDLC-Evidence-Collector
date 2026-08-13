"""Local artifact collector.

Walks configured directories and produces `NormalizedEvidence` records from
the files it recognizes. File type detection is based on extension and
content sniffing when needed.
"""

from __future__ import annotations

import codecs
import json
import logging
import os
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
    normalize_intoto_statement,
    normalize_junit,
    normalize_lm_eval,
    normalize_model_card,
    normalize_osv,
    normalize_provenance,
    normalize_registry_attestation,
    normalize_release_attestation,
    normalize_sarif,
    normalize_sbom,
    normalize_trivy_json,
    normalize_vsa,
    normalize_zap,
)
from evidence_collector.parsers import (
    parse_attestation,
    parse_exception,
    parse_garak,
    parse_intoto_statements,
    parse_junit,
    parse_lm_eval,
    parse_model_card,
    parse_osv,
    parse_provenances,
    parse_registry_attestation,
    parse_release_attestations,
    parse_sarifs,
    parse_sbom,
    parse_trivy_json,
    parse_vsa,
    parse_zap,
)
from evidence_collector.parsers._common import MAX_INPUT_BYTES, ParseError
from evidence_collector.parsers._intoto import read_records
from evidence_collector.parsers.intoto_provenance import file_has_provenance
from evidence_collector.parsers.intoto_statement import file_has_ingestable_statement
from evidence_collector.parsers.intoto_vsa import VSA_PREDICATE_TYPE
from evidence_collector.parsers.registry_attestation import looks_like_registry_attestation
from evidence_collector.parsers.release_attestation import file_has_release_attestation
from evidence_collector.parsers.sbom import is_spdx3
from evidence_collector.parsers.trivy_json import looks_like_trivy_json
from evidence_collector.paths import redact_path_in, relative_to_root

logger = logging.getLogger(__name__)


@dataclass
class LocalCollectionError:
    path: Path
    reason: str


# Fields that legitimately differ between two reads of one artifact, and so
# must not make two records look like different evidence. `collected_at` is a
# wall-clock stamp taken per record, so two reads differ by microseconds; the
# structural-hash normaliser calls it volatile for the same reason. It is
# restated here rather than imported because `collectors` sits below
# `application` in the layering — `test_local_collector` pins the two together.
_VOLATILE_EVIDENCE_FIELDS = {"collected_at"}
_LOCATION_FIELDS_IN_RAW = {"artifact_path", "artifact_uri"}


def _artifact_location(evidence: NormalizedEvidence) -> str:
    """Best available description of where an evidence record was read from."""
    raw = evidence.raw
    if raw is None:
        return evidence.evidence_id
    return raw.artifact_path or raw.artifact_uri or evidence.evidence_id


def _same_evidence_apart_from_path(first: NormalizedEvidence, second: NormalizedEvidence) -> bool:
    """Whether two records are the same evidence read from two locations.

    The comparison ignores exactly the fields that legitimately differ
    between two copies of one artifact — where it was found — and nothing
    else. Anything beyond that means the shared id is a real collision, not
    a duplicate supply, and the caller must not discard either record.
    """
    ignore = {"raw"} | _VOLATILE_EVIDENCE_FIELDS
    if first.model_dump(exclude=ignore) != second.model_dump(exclude=ignore):
        return False
    if first.raw is None or second.raw is None:
        return first.raw is second.raw
    return first.raw.model_dump(exclude=_LOCATION_FIELDS_IN_RAW) == second.raw.model_dump(
        exclude=_LOCATION_FIELDS_IN_RAW
    )


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

    def _record_error(self, report: LocalCollectionReport, path: Path, reason: str) -> None:
        """Record a failed input, with its path rewritten against the artifact root.

        `--artifact-root` exists so a published bundle records repo-relative
        paths "instead of leaking local filesystem locations". Collection
        errors were exempt from that: `collection_errors[].path` carried the
        absolute path, and so did `reason`, which embeds the path in the
        parser's own message. So a run that set the flag precisely to avoid
        publishing `/home/alice/clients/acme/...` published it anyway — in the
        one part of the bundle nobody thinks to check, and only when something
        had already gone wrong.
        """
        relative = relative_to_root(path, self._artifact_root)
        report.errors.append(
            LocalCollectionError(path=relative, reason=redact_path_in(reason, path, relative))
        )

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
            self._record_error(report, directory, "directory not found")
            return False
        if not directory.is_dir():
            self._record_error(
                report,
                directory,
                "not a directory (expected a folder; pass the containing folder, "
                "not a single file)",
            )
            return False
        return True

    def _walk_once(self, directories: list[Path], report: LocalCollectionReport) -> list[Path]:
        """Return every file under ``directories``, each exactly once.

        ``--artifacts-dir`` is documented as repeatable, and nothing stopped
        a caller from passing a directory and one of its own subdirectories
        (a parent plus a scanner-specific folder, or a CI matrix that appends
        paths). ``rglob`` then yielded the nested files under both roots, so
        every one of them was ingested twice: the bundle carried duplicate
        evidence with *colliding* ``evidence_id`` values — the id is derived
        from the artifact hash and context, so the same file always produces
        the same id — and the coverage and confidence scores were computed
        over the inflated set.

        Paths are resolved before de-duplication so a parent/child overlap,
        a symlink, and a case difference on Windows all collapse to one
        entry. Order stays deterministic: directories in the order given,
        files sorted within each.
        """
        seen: set[Path] = set()
        ordered: list[Path] = []
        for directory in directories:
            if not self._usable_directory(directory, report):
                continue
            for file_path in self._walk_tree(directory, report):
                try:
                    key = file_path.resolve()
                except OSError:
                    key = file_path.absolute()
                if key in seen:
                    continue
                seen.add(key)
                ordered.append(file_path)
        return ordered

    def _walk_tree(self, directory: Path, report: LocalCollectionReport) -> list[Path]:
        """Return every file under ``directory``, reporting what could not be read.

        This used to be ``directory.rglob("*")``. CPython's glob machinery
        swallows the ``PermissionError`` / ``OSError`` that ``os.scandir``
        raises on a directory it cannot descend into, so an unreadable
        subdirectory simply produced no entries: its evidence vanished, the
        run exited on a `not_ready` verdict citing missing critical evidence,
        and no warning was printed anywhere. The scans had run; the collector
        just could not see them and did not say so.

        ``os.walk`` with an ``onerror`` callback turns that back into a
        recorded failure. Sorting is preserved so ordering stays deterministic
        (docs/limitations.md §8).
        """
        found: list[Path] = []

        def _on_error(exc: OSError) -> None:
            path = Path(exc.filename) if exc.filename else directory
            reason = f"Could not read directory {path}: {exc.strerror or exc}"
            logger.warning("%s", reason)
            self._record_error(report, path, reason)

        for root, dir_names, file_names in os.walk(directory, onerror=_on_error):
            dir_names.sort()
            root_path = Path(root)
            found.extend(root_path / name for name in sorted(file_names))
        return found

    def collect(self) -> LocalCollectionReport:
        report = LocalCollectionReport()
        for file_path in self._walk_once(self._artifacts_dirs, report):
            report.inspected_files += 1
            self._ingest_artifact(file_path, report)
        for file_path in self._walk_once(self._attestations_dirs, report):
            report.inspected_files += 1
            self._ingest_attestation(file_path, report)
        for file_path in self._walk_once(self._exceptions_dirs, report):
            report.inspected_files += 1
            self._ingest_exception(file_path, report)
        report.evidence = self._deduplicate_evidence(report.evidence, report)
        return report

    @staticmethod
    def _deduplicate_evidence(
        evidence: list[NormalizedEvidence], report: LocalCollectionReport
    ) -> list[NormalizedEvidence]:
        """Collapse records that describe the same evidence found twice.

        ``evidence_id`` is a digest of the artifact's content hash plus its
        tool and release context, so the *same bytes* supplied at two paths
        produce the same id — two CI jobs uploading one scanner's SARIF into
        their own folder is enough. Nothing rejected that: the bundle carried
        two records under one id, and `evidence_refs` stopped identifying a
        single record, in a tool whose entire product is traceability. A
        consumer doing the obvious ``{e.evidence_id: e for e in evidence}``
        silently kept whichever came last.

        Two records sharing an id are the same evidence and differ only in
        where it was read from, so the first (walk order is deterministic) is
        kept and the duplicate path is recorded on it.

        If they differ in substance, that is not a duplicate supply but a
        genuine id collision — dropping one would lose real evidence, so it
        is reported instead and both are kept for the model to reject.
        """
        kept: dict[str, NormalizedEvidence] = {}
        order: list[str] = []
        collisions: list[NormalizedEvidence] = []
        for item in evidence:
            first = kept.get(item.evidence_id)
            if first is None:
                kept[item.evidence_id] = item
                order.append(item.evidence_id)
                continue
            if _same_evidence_apart_from_path(first, item):
                logger.info(
                    "Ignoring duplicate evidence %s: %s is the same artifact already "
                    "ingested from %s",
                    item.evidence_id,
                    _artifact_location(item),
                    _artifact_location(first),
                )
                continue
            reason = (
                f"evidence id {item.evidence_id} was derived for two different "
                f"records ({_artifact_location(first)} and {_artifact_location(item)}); "
                "the bundle cannot reference either one unambiguously"
            )
            logger.error("%s", reason)
            report.errors.append(
                LocalCollectionError(path=Path(_artifact_location(item)), reason=reason)
            )
            collisions.append(item)
        return [kept[key] for key in order] + collisions

    def _ingest_exception(self, file_path: Path, report: LocalCollectionReport) -> None:
        suffix = file_path.suffix.lower()
        if suffix not in {".yaml", ".yml", ".json"}:
            return
        try:
            report.exceptions.append(parse_exception(file_path))
        except (ParseError, OSError) as exc:
            logger.warning("Failed to ingest exception %s: %s", file_path, exc)
            self._record_error(report, file_path, str(exc))

    def _ingest_artifact(self, file_path: Path, report: LocalCollectionReport) -> None:
        suffix = file_path.suffix.lower()
        try:
            if suffix in {".sarif", ".sarif.json"} or _looks_like_sarif(file_path):
                # One evidence per SARIF ``runs[]`` entry. A merged file — what
                # `trivy fs --format sarif` and most aggregators emit — carries
                # one run per tool, each with its own `tool.driver.name`, which
                # is exactly what the classifier reads. Taking only runs[0]
                # made every later run vanish: a semgrep+gitleaks+trivy file
                # produced a single `sast_scan`, and the release reported the
                # secrets and SCA controls as missing critical evidence while
                # both scans had in fact been supplied.
                for parsed in parse_sarifs(file_path):
                    report.evidence.append(
                        normalize_sarif(parsed, self._release, artifact_root=self._artifact_root)
                    )
                return
            # Native Trivy JSON. Checked early because it is the only
            # artifact that yields SEVERAL evidences from one file: Trivy
            # separates dependency, secret and IaC findings by
            # ``Results[].Class`` and each becomes its own evidence.
            if _looks_like_trivy_json(file_path):
                parsed_trivy = parse_trivy_json(file_path)
                report.evidence.extend(
                    normalize_trivy_json(
                        parsed_trivy, self._release, artifact_root=self._artifact_root
                    )
                )
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
            # Package-registry attestations (PyPI PEP 740, npm). These are
            # not in-toto Statements at the top level — they are registry
            # envelopes *around* Statements — so they get their own route
            # ahead of the in-toto block rather than competing with it.
            if _looks_like_registry_attestation(file_path):
                parsed_reg = parse_registry_attestation(file_path)
                report.evidence.append(
                    normalize_registry_attestation(
                        parsed_reg, self._release, artifact_root=self._artifact_root
                    )
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
                for parsed_prov in parse_provenances(file_path):
                    report.evidence.append(
                        normalize_provenance(
                            parsed_prov, self._release, artifact_root=self._artifact_root
                        )
                    )
                intoto_found = True
            if _looks_like_release_attestation(file_path):
                for parsed_rel in parse_release_attestations(file_path):
                    report.evidence.append(
                        normalize_release_attestation(
                            parsed_rel, self._release, artifact_root=self._artifact_root
                        )
                    )
                intoto_found = True
            # Anything else that is still a valid in-toto Statement. Known
            # predicates (SVR, test-result, vulns) map to a real evidence
            # type; an unknown one is recorded as a generic attestation with
            # a warning. Before this route existed such a Statement was
            # dropped silently — the user got a bundle with no trace of a
            # file they believed they had supplied.
            if _looks_like_intoto_statement(file_path):
                for parsed_stmt in parse_intoto_statements(file_path):
                    if not parsed_stmt.recognized:
                        logger.warning(
                            "Ingesting %s as a generic attestation: unrecognized in-toto "
                            "predicate %s",
                            file_path,
                            parsed_stmt.predicate_type,
                        )
                    report.evidence.append(
                        normalize_intoto_statement(
                            parsed_stmt, self._release, artifact_root=self._artifact_root
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
                self._record_error(report, file_path, encoding_error)
                return
            # A .json/.jsonl file that is not valid JSON is a THIRD case: not
            # an unknown format, not an unreadable byte stream, but a file the
            # caller plainly meant as evidence and which is broken. It used to
            # fall through to the debug line below and vanish — while a file
            # with byte-identical content named .sarif produced a warning,
            # purely because the SARIF branch parses eagerly and raises.
            # Truncated scanner output is exactly how this happens in a
            # pipeline, and a report that silently understates coverage is
            # worse than one that errors.
            json_error = _malformed_json_reason(file_path)
            if json_error is not None:
                logger.warning("Failed to ingest %s: %s", file_path, json_error)
                self._record_error(report, file_path, json_error)
                return
            logger.debug("Ignoring unrecognized artifact: %s", file_path)
        except (ParseError, OSError) as exc:
            logger.warning("Failed to ingest %s: %s", file_path, exc)
            self._record_error(report, file_path, str(exc))

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
            self._record_error(report, file_path, str(exc))


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


def _looks_like_trivy_json(path: Path) -> bool:
    """Detect a native Trivy JSON report. Reuses the memoized peek."""
    if path.suffix.lower() != ".json":
        return False
    return looks_like_trivy_json(_peek_json(path))


def _looks_like_registry_attestation(path: Path) -> bool:
    """Detect a PyPI (PEP 740) provenance/attestation object or an npm
    attestations payload. Reuses the memoized peek — these are ordinary
    single-document JSON, so no extra read is needed."""
    if path.suffix.lower() != ".json":
        return False
    return looks_like_registry_attestation(_peek_json(path))


def _looks_like_intoto_statement(path: Path) -> bool:
    """Detect any in-toto Statement no dedicated parser already claims —
    in a raw Statement, a DSSE envelope, a Sigstore bundle, or a JSONL
    record."""
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return False
    return file_has_ingestable_statement(path)


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


def _malformed_json_reason(path: Path) -> str | None:
    """Return why a ``.json``/``.jsonl`` artifact is not valid JSON, or None.

    Called only on the fallthrough, after every detector has declined the
    file. A caller who drops `report.json` into the artifacts directory means
    it as evidence; if it does not parse, saying so is the difference between
    a report that understates coverage and one that explains why.

    A ``.jsonl`` is valid when *any* line parses as a JSON object — that is
    the shape the in-toto detectors accept — so a partially written JSONL is
    only reported when nothing at all could be read from it.
    """
    suffix = path.suffix.lower()
    if suffix not in {".json", ".jsonl"}:
        return None

    # Both lookups below are memoized and were already populated by the
    # detectors, so the common case costs no extra read. Doing the parse
    # unconditionally here added a fourth open to every candidate file and
    # broke the detection-read bound.
    if suffix == ".jsonl":
        return None if read_records(path) else f"No JSON records could be read from {path}."
    if _peek_json(path) is not None:
        return None

    # Only now, on a file we are already about to call broken, is a re-read
    # worth it: the caller deserves the parse position, and this path is by
    # definition rare.
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # Reported by the encoding probe and the size check, which run first.
        return None
    if not text.strip():
        return f"File {path} is empty."
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return f"Invalid JSON in {path}: {exc}"
    return None


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
