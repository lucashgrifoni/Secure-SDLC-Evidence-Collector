"""Package-registry attestation parser — PyPI (PEP 740) and npm.

Both registries now publish, alongside a release, a signed statement of
*who published it and from where*. That is release evidence the collector
could not read: a package may carry perfect build provenance and still
have been uploaded by the wrong identity, and the registry's own record
is the only thing that says otherwise.

**PyPI — PEP 740** (Final; operational since 2024-11-14). Two shapes are
accepted:

* the *provenance object* the Integrity API serves —
  ``{"version": 1, "attestation_bundles": [{"publisher": {...},
  "attestations": [...]}]}``; and
* a single *attestation object* — ``{"version": 1,
  "verification_material": {...}, "envelope": {"statement": "<base64>",
  "signature": "<base64>"}}``.

``publisher.kind`` is recorded verbatim as a **string**, never an enum.
PEP 740 says the value "uniquely identifies the kind of Trusted
Publisher" and that every other key in the object is publisher-specific;
pinning it to a closed set would break the first time a registry adds a
publisher type.

**npm.** The registry's attestations endpoint returns
``{"attestations": [{"predicateType": "...", "bundle": {...}}]}`` where
each ``bundle`` is a Sigstore bundle carrying a ``dsseEnvelope`` — the
shape :mod:`evidence_collector.parsers._intoto` already unwraps.

**No network access.** The collector never calls a registry. The user
saves the JSON — ``curl`` from the Integrity API, or the npm attestations
endpoint — exactly as they already do for ``gh attestation download``.

What this parser records is the *envelope of publication*: which
registry, which publisher kind, and the predicate types the bundle
carries. It deliberately does not emit separate evidence per embedded
predicate — see ``docs/limitations.md``.

Scope (see ``docs/limitations.md``): decoded, never verified. The
certificate and transparency-log entries are read past, not checked.
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
from evidence_collector.parsers._intoto import decode_b64_statement, first_subject_name, unwrap

REGISTRY_PYPI = "pypi"
REGISTRY_NPM = "npm"


@dataclass(frozen=True)
class EmbeddedStatement:
    """One in-toto Statement carried inside a registry attestation."""

    predicate_type: str
    subject_name: str | None


@dataclass
class ParsedRegistryAttestation:
    artifact: ParsedArtifact
    registry: str
    statements: list[EmbeddedStatement] = field(default_factory=list)
    publisher_kind: str | None = None
    publisher_claim_keys: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _statement_from(statement: dict[str, Any] | None) -> EmbeddedStatement | None:
    if statement is None:
        return None
    predicate_type = _optional_str(statement.get("predicateType"))
    if predicate_type is None:
        return None
    return EmbeddedStatement(
        predicate_type=predicate_type,
        subject_name=first_subject_name(statement),
    )


def _from_pep740_attestation(attestation: Any) -> EmbeddedStatement | None:
    """Decode one PEP 740 attestation object's ``envelope.statement``."""
    if not isinstance(attestation, dict):
        return None
    envelope = attestation.get("envelope")
    if not isinstance(envelope, dict):
        return None
    return _statement_from(decode_b64_statement(envelope.get("statement")))


def _is_pypi_provenance(data: dict[str, Any]) -> bool:
    return isinstance(data.get("attestation_bundles"), list)


def _is_pypi_attestation(data: dict[str, Any]) -> bool:
    envelope = data.get("envelope")
    return isinstance(envelope, dict) and isinstance(envelope.get("statement"), str)


def _is_npm_attestations(data: dict[str, Any]) -> bool:
    entries = data.get("attestations")
    if not isinstance(entries, list) or not entries:
        return False
    return any(isinstance(entry, dict) and "bundle" in entry for entry in entries)


def looks_like_registry_attestation(data: Any) -> bool:
    """True when ``data`` is a PyPI or npm attestation document.

    Takes already-parsed data rather than a path so the collector can feed
    it from the memoized JSON peek shared by the other detectors. Reading
    the file again here would add a fourth open per candidate and break
    the detection-read bound that ``test_detection_does_not_reread_the_
    same_file_for_every_probe`` guards.
    """
    if not isinstance(data, dict):
        return False
    return _is_pypi_provenance(data) or _is_pypi_attestation(data) or _is_npm_attestations(data)


def _parse_pypi_provenance(data: dict[str, Any], parsed: ParsedRegistryAttestation) -> None:
    bundles = data.get("attestation_bundles")
    if not isinstance(bundles, list):
        return
    for bundle in bundles:
        if not isinstance(bundle, dict):
            continue
        publisher = bundle.get("publisher")
        if isinstance(publisher, dict) and parsed.publisher_kind is None:
            # Open string by spec — recorded as given, never mapped to an enum.
            parsed.publisher_kind = _optional_str(publisher.get("kind"))
            claims = publisher.get("claims")
            if isinstance(claims, dict):
                # Only the claim *names*: the values are publisher-specific
                # and can carry repository and workflow detail that does not
                # belong in a bundle by default.
                parsed.publisher_claim_keys = sorted(key for key in claims if isinstance(key, str))
        attestations = bundle.get("attestations")
        if not isinstance(attestations, list):
            continue
        for attestation in attestations:
            embedded = _from_pep740_attestation(attestation)
            if embedded is not None:
                parsed.statements.append(embedded)


def _parse_npm(data: dict[str, Any], parsed: ParsedRegistryAttestation) -> None:
    entries = data.get("attestations")
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        bundle = entry.get("bundle")
        embedded: EmbeddedStatement | None = None
        if isinstance(bundle, dict):
            statement, _envelope = unwrap(bundle)
            embedded = _statement_from(statement)
        if embedded is None:
            # npm states the predicate type alongside the bundle, so a
            # bundle we cannot decode still yields the type it claimed.
            declared = _optional_str(entry.get("predicateType"))
            if declared is not None:
                embedded = EmbeddedStatement(predicate_type=declared, subject_name=None)
        if embedded is not None:
            parsed.statements.append(embedded)


def parse_registry_attestation(path: str | Path) -> ParsedRegistryAttestation:
    resolved = ensure_file(path)
    data = load_json(resolved)

    if _is_npm_attestations(data):
        registry = REGISTRY_NPM
    elif _is_pypi_provenance(data) or _is_pypi_attestation(data):
        registry = REGISTRY_PYPI
    else:
        raise ParseError(f"File {resolved} is not a PyPI (PEP 740) or npm registry attestation.")

    parsed = ParsedRegistryAttestation(
        artifact=describe(resolved, content_type="application/json"),
        registry=registry,
        raw=data,
    )

    if registry == REGISTRY_NPM:
        _parse_npm(data, parsed)
    elif _is_pypi_provenance(data):
        _parse_pypi_provenance(data, parsed)
    else:
        embedded = _from_pep740_attestation(data)
        if embedded is not None:
            parsed.statements.append(embedded)

    if not parsed.statements:
        raise ParseError(f"Registry attestation {resolved} carries no decodable in-toto Statement.")
    return parsed
