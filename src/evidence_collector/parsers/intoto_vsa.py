"""SLSA Verification Summary Attestation (VSA) parser.

A VSA (https://slsa.dev/spec/v1.0/verification_summary) is an in-toto
attestation in which a *verifier* states that it evaluated one or more
artifacts against a policy and records the resulting SLSA levels. It is
release-readiness evidence in the purest sense: "an independent verifier
confirmed this artifact met level X", which is exactly the kind of signal
the collector normalizes — distinct from re-running the verification.

This parser reads a **raw in-toto Statement v1** carrying the VSA
predicate::

    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": "...", "digest": {"sha256": "..."}}],
      "predicateType": "https://slsa.dev/verification_summary/v1",
      "predicate": {
        "verifier": {"id": "https://example.com/publication_verifier"},
        "timeVerified": "2026-06-17T00:00:00Z",
        "resourceUri": "pkg:...",
        "policy": {"uri": "https://example.com/policy", "digest": {...}},
        "verificationResult": "PASSED",
        "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
        "inputAttestations": [{"uri": "...", "digest": {...}}],
        "slsaVersion": "1.0"
      }
    }

The predicate fields ``verifier`` (with ``id``), ``timeVerified``,
``resourceUri``, ``policy``, ``verificationResult``, and ``verifiedLevels``
are **required** by the spec and by this parser: an incomplete or anonymous
VSA is rejected rather than normalized, so a malformed attestation can never
make a release-integrity control look met. ``inputAttestations``,
``slsaVersion``, and ``policy.uri`` are optional.

Scope (see ``docs/limitations.md``): the collector records the *presence*
and the *stated* result of the VSA. It does **not** verify the VSA's
signature or re-evaluate the policy — DSSE-wrapped / signed envelopes
should be verified upstream; this parser consumes the decoded Statement.
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

VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"


@dataclass
class ParsedVsa:
    artifact: ParsedArtifact
    verification_result: str
    verifier_id: str
    resource_uri: str
    time_verified: str
    verified_levels: list[str]
    policy_uri: str | None = None
    slsa_version: str | None = None
    subject_name: str | None = None
    input_attestation_count: int = 0
    raw: dict[str, Any] = field(default_factory=dict)


def _first_subject_name(data: dict[str, Any]) -> str | None:
    subjects = data.get("subject")
    if not isinstance(subjects, list):
        return None
    for entry in subjects:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str) and name:
                return name
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def parse_vsa(path: str | Path) -> ParsedVsa:
    resolved = ensure_file(path)
    data = load_json(resolved)

    if data.get("predicateType") != VSA_PREDICATE_TYPE:
        raise ParseError(
            f"File {resolved} is not a SLSA VSA: expected predicateType "
            f"'{VSA_PREDICATE_TYPE}', got '{data.get('predicateType')}'."
        )

    predicate = data.get("predicate")
    if not isinstance(predicate, dict):
        raise ParseError(f"VSA {resolved} is missing a 'predicate' object.")

    # Required VSA predicate fields per
    # https://slsa.dev/spec/v1.0/verification_summary. An incomplete or
    # anonymous VSA is rejected rather than silently treated as a passing
    # attestation that could satisfy a release-integrity control.
    verifier = predicate.get("verifier")
    verifier_id = _optional_str(verifier.get("id")) if isinstance(verifier, dict) else None
    if verifier_id is None:
        raise ParseError(f"VSA {resolved} is missing required field 'verifier.id'.")

    verification_result = _optional_str(predicate.get("verificationResult"))
    if verification_result is None:
        raise ParseError(f"VSA {resolved} is missing required field 'verificationResult'.")

    time_verified = _optional_str(predicate.get("timeVerified"))
    if time_verified is None:
        raise ParseError(f"VSA {resolved} is missing required field 'timeVerified'.")

    resource_uri = _optional_str(predicate.get("resourceUri"))
    if resource_uri is None:
        raise ParseError(f"VSA {resolved} is missing required field 'resourceUri'.")

    policy = predicate.get("policy")
    if not isinstance(policy, dict):
        raise ParseError(f"VSA {resolved} is missing required field 'policy'.")

    verified_levels = _string_list(predicate.get("verifiedLevels"))
    if not verified_levels:
        raise ParseError(f"VSA {resolved} is missing required field 'verifiedLevels'.")

    input_attestations = predicate.get("inputAttestations")
    input_count = len(input_attestations) if isinstance(input_attestations, list) else 0

    artifact = describe(resolved, content_type="application/json")
    return ParsedVsa(
        artifact=artifact,
        verification_result=verification_result.upper(),
        verifier_id=verifier_id,
        resource_uri=resource_uri,
        time_verified=time_verified,
        verified_levels=verified_levels,
        policy_uri=_optional_str(policy.get("uri")),
        slsa_version=_optional_str(predicate.get("slsaVersion")),
        subject_name=_first_subject_name(data),
        input_attestation_count=input_count,
        raw=data,
    )
