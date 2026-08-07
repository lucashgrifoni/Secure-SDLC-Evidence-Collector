"""Generic in-toto Statement ingestion — including predicates we do not know.

Before this parser, an in-toto Statement whose ``predicateType`` had no
dedicated route was **silently dropped**. The collector recognized SLSA
provenance, VSAs and release attestations; everything else fell through
the detector chain and was logged at debug level as "unrecognized
artifact". A user who exported a signed attestation and pointed the
collector at it got a bundle with no trace of it and no warning — the
same class of silent evidence loss as the mixed-JSONL bug.

This module closes that hole in two layers.

**Recognized predicates** get a real mapping, because in-toto vets them
and their shapes are stable:

* ``svr/v0.2`` — Simple Verification Result: a third party states which
  properties it verified. Lands as ``artifact_attestation``.
* ``test-result/v0.1`` — a test run with a ``PASSED`` / ``WARNED`` /
  ``FAILED`` verdict. Lands as ``test_result``.
* ``vulns/v0.2`` — a vulnerability scan with scanner identity and
  findings. Lands as ``sca_scan``, so it flows through the same
  enrichment lane as OSV and Trivy output.

**Everything else** becomes ``generic_attestation`` with the predicate
type recorded verbatim, and the collector emits a warning naming the
predicate it did not understand. Present-but-unmodelled is a far better
failure mode than absent-and-silent: the reviewer can see that something
was supplied and decide what it is worth.

Predicates that already have a dedicated parser are deliberately *not*
claimed here — see ``_is_claimed_elsewhere``.

Known gap: ``spdx3/v0.1`` should route its predicate to the SBOM parser,
but ``parse_sbom`` is path-based and reshaping it to accept an in-memory
document is a change to the largest parser in the tree. Until then an
SPDX 3 Statement is ingested as a generic attestation — recorded, not
lost, but not parsed as an SBOM.

Scope (see ``docs/limitations.md``): decoded, never verified.
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
)
from evidence_collector.parsers._intoto import (
    file_has_statement,
    find_statement,
    first_subject_name,
    iter_record_dicts,
)
from evidence_collector.parsers.intoto_provenance import SLSA_PROVENANCE_PREFIX
from evidence_collector.parsers.release_attestation import RELEASE_PREDICATE_TYPES

SVR_PREDICATE_TYPE = "https://in-toto.io/attestation/svr/v0.2"
TEST_RESULT_PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
VULNS_PREDICATE_TYPE = "https://in-toto.io/attestation/vulns/v0.2"

RECOGNIZED_PREDICATE_TYPES = frozenset(
    {SVR_PREDICATE_TYPE, TEST_RESULT_PREDICATE_TYPE, VULNS_PREDICATE_TYPE}
)

# Qualitative severity words we accept from a vulns predicate. The spec
# lets `severity.score` be either a word ("medium") or a number ("5.2"),
# and the method naming it is free-form. Anything outside this set is
# counted as `unknown` rather than guessed into a bucket — a mis-bucketed
# critical would silently change a release verdict.
_SEVERITY_BUCKETS = frozenset({"critical", "high", "medium", "low", "none", "info"})


@dataclass
class ParsedIntotoStatement:
    artifact: ParsedArtifact
    predicate_type: str
    envelope: str
    recognized: bool
    subject_name: str | None = None
    # svr/v0.2
    verifier_id: str | None = None
    properties: list[str] = field(default_factory=list)
    time_created: str | None = None
    # test-result/v0.1
    test_result: str | None = None
    passed_tests: int = 0
    warned_tests: int = 0
    failed_tests: int = 0
    test_url: str | None = None
    # vulns/v0.2
    scanner_uri: str | None = None
    scanner_version: str | None = None
    vuln_ids: list[str] = field(default_factory=list)
    findings_count: dict[str, int] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _is_claimed_elsewhere(predicate_type: str) -> bool:
    """True for predicates whose dedicated parser reads *every* envelope.

    Those routes extract far more than this module can, so claiming them
    here would downgrade the evidence.

    The VSA predicate is deliberately **absent** from this list even
    though ``intoto_vsa.py`` exists. That parser reads a raw Statement
    only — a DSSE-wrapped or Sigstore-bundled VSA is invisible to it (a
    documented limitation: the payload is base64). Excluding the
    predicate here would mean a signed VSA is claimed by nobody and
    vanishes. Instead it falls through to this module and is recorded as
    a generic attestation. A raw-Statement VSA never reaches here: the
    collector's own VSA detector matches it first and returns.
    """
    return (
        predicate_type.startswith(SLSA_PROVENANCE_PREFIX)
        or predicate_type in RELEASE_PREDICATE_TYPES
    )


def _is_ingestable(predicate_type: str) -> bool:
    return not _is_claimed_elsewhere(predicate_type)


def file_has_ingestable_statement(path: Path) -> bool:
    """True when ``path`` holds an in-toto Statement that no dedicated
    parser already claims. Used by the local collector for detection;
    never raises on an unreadable file."""
    return file_has_statement(path, _is_ingestable)


def _extract_svr(predicate: dict[str, Any], parsed: ParsedIntotoStatement) -> None:
    verifier = predicate.get("verifier")
    if isinstance(verifier, dict):
        parsed.verifier_id = _optional_str(verifier.get("id"))
    parsed.properties = _string_list(predicate.get("properties"))
    parsed.time_created = _optional_str(predicate.get("timeCreated"))


def _extract_test_result(predicate: dict[str, Any], parsed: ParsedIntotoStatement) -> None:
    result = _optional_str(predicate.get("result"))
    parsed.test_result = result.upper() if result else None
    parsed.passed_tests = len(_string_list(predicate.get("passedTests")))
    parsed.warned_tests = len(_string_list(predicate.get("warnedTests")))
    parsed.failed_tests = len(_string_list(predicate.get("failedTests")))
    parsed.test_url = _optional_str(predicate.get("url"))


def _vuln_severity_bucket(entry: dict[str, Any]) -> str:
    """Return the severity bucket for one vulns result entry.

    ``severity`` is a list of ``{method, score}`` pairs; the same finding
    can carry both a qualitative NVD word and a numeric CVSS score. We
    take the first qualitative word we recognize and fall back to
    ``unknown`` — never parsing a number into a bucket, since the cut
    points differ per scoring system.
    """
    severities = entry.get("severity")
    if not isinstance(severities, list):
        return "unknown"
    for severity in severities:
        if not isinstance(severity, dict):
            continue
        score = _optional_str(severity.get("score"))
        if score and score.lower() in _SEVERITY_BUCKETS:
            return score.lower()
    return "unknown"


def _extract_vulns(predicate: dict[str, Any], parsed: ParsedIntotoStatement) -> None:
    scanner = predicate.get("scanner")
    if not isinstance(scanner, dict):
        return
    parsed.scanner_uri = _optional_str(scanner.get("uri"))
    parsed.scanner_version = _optional_str(scanner.get("version"))
    results = scanner.get("result")
    if not isinstance(results, list):
        return
    counts: dict[str, int] = {}
    for entry in results:
        if not isinstance(entry, dict):
            continue
        vuln_id = _optional_str(entry.get("id"))
        if vuln_id is None:
            continue
        parsed.vuln_ids.append(vuln_id)
        bucket = _vuln_severity_bucket(entry)
        counts[bucket] = counts.get(bucket, 0) + 1
    parsed.findings_count = counts


def parse_intoto_statement(path: str | Path) -> ParsedIntotoStatement:
    resolved = ensure_file(path)
    try:
        text = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"Invalid text encoding in {resolved}: {exc}") from exc

    records = iter_record_dicts(text)
    if not records:
        raise ParseError(f"File {resolved} is not a JSON object or a JSONL of objects.")

    found = find_statement(records, _is_ingestable)
    if found is None:
        raise ParseError(
            f"File {resolved} contains no ingestable in-toto Statement across "
            f"{len(records)} record(s)."
        )
    record, statement, envelope = found
    predicate_type = statement["predicateType"]

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        # An unknown predicate with no body is still worth recording: the
        # Statement asserts *something* about the subject, and dropping it
        # is the behaviour this parser exists to end.
        predicate = {}

    parsed = ParsedIntotoStatement(
        artifact=describe(resolved, content_type="application/json"),
        predicate_type=predicate_type,
        envelope=envelope,
        recognized=predicate_type in RECOGNIZED_PREDICATE_TYPES,
        subject_name=first_subject_name(statement),
        raw=record,
    )

    if predicate_type == SVR_PREDICATE_TYPE:
        _extract_svr(predicate, parsed)
    elif predicate_type == TEST_RESULT_PREDICATE_TYPE:
        _extract_test_result(predicate, parsed)
    elif predicate_type == VULNS_PREDICATE_TYPE:
        _extract_vulns(predicate, parsed)

    return parsed
