"""in-toto Statement v1 exporter.

Wraps a canonical :class:`EvidenceBundle` as an in-toto Statement
(predicateType ``https://github.com/lucashgrifoni/secure-sdlc-evidence-collector/predicate/sdlc-evidence/v1``)
so the bundle becomes self-describing supply-chain metadata that any
in-toto / Sigstore verifier can ingest without bespoke code.

Why this matters

* ``cosign sign-blob`` already covers signing the raw bundle.json, but
  the resulting signature carries no schema information — a verifier
  cannot tell from the cosign envelope alone that the blob is a Secure
  SDLC evidence bundle. Wrapping the bundle in an in-toto Statement
  declares the predicate type explicitly.

* in-toto v1 Statements are the input shape Sigstore consumes for
  ``cosign attest`` and what tools like GUAC, Kyverno, and OPA
  Gatekeeper recognize. Emitting Statement-shaped output here closes
  the gap to that ecosystem with zero changes to the bundle schema.

Spec references

* in-toto Statement v1: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
* DSSE envelope: https://github.com/secure-systems-lab/dsse/blob/master/envelope.md
* Sigstore cosign --new-bundle-format: https://blog.sigstore.dev/cosign-3-0-available/

Note on signing

This module ONLY produces the in-toto Statement; it does NOT sign it.
Signing should be performed externally (cosign keyless, ssh-keygen,
custom KMS). Keeping signing out of process keeps the collector free of
private-key handling, which is the right boundary for an audit tool.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Literal

from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.domain.models import EvidenceBundle

IN_TOTO_TYPE = "https://in-toto.io/Statement/v1"

# Project-native predicate type (default). Used when the consumer treats
# the bundle as self-describing evidence and does not need to plug into
# an external attestation ecosystem.
PREDICATE_TYPE = (
    "https://github.com/lucashgrifoni/secure-sdlc-evidence-collector/predicate/sdlc-evidence/v1"
)
PREDICATE_TYPE_EVIDENCE_BUNDLE = PREDICATE_TYPE

# Witness-compatible variant. Witness (https://witness.dev) uses in-toto
# Statement v1 envelopes with per-attestor predicate types under the
# witness.dev namespace. The collector emits a single product-shaped
# attestation that carries the bundle as a custom payload so Witness
# verifiers ingest it without bespoke parsers.
PREDICATE_TYPE_WITNESS = "https://witness.dev/attestations/custom/sdlc-evidence/v0.1"

# SLSA Provenance v1 variant. Useful when the bundle should travel
# alongside or in place of a SLSA provenance attestation (GUAC,
# slsa-verifier, Kyverno). We keep the bundle as the predicate payload
# and let the consumer derive build metadata from it.
PREDICATE_TYPE_SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"

PredicateType = Literal["evidence-bundle", "witness", "slsa-provenance"]

_PREDICATE_TYPE_BY_NAME: dict[PredicateType, str] = {
    "evidence-bundle": PREDICATE_TYPE_EVIDENCE_BUNDLE,
    "witness": PREDICATE_TYPE_WITNESS,
    "slsa-provenance": PREDICATE_TYPE_SLSA_PROVENANCE,
}


def predicate_type_url(name: PredicateType) -> str:
    """Return the canonical URL for a registered predicate-type name.

    Centralising this mapping keeps the CLI and exporter in agreement
    on the wire format and lets future predicate-type variants be added
    without touching every caller.
    """
    return _PREDICATE_TYPE_BY_NAME[name]


def _bundle_payload(bundle: EvidenceBundle) -> dict[str, Any]:
    """Return the bundle as a ``dict`` with timestamps preserved.

    The Statement embeds the full bundle as the predicate. Volatile
    fields (``bundle_id``, ``generated_at``, ``collected_at``,
    ``evaluated_at``, ``enriched_at``) ARE preserved here because the
    Statement is a moment-in-time snapshot — readers who want
    structural-only equivalence should re-normalize via
    :func:`evidence_collector.application.integrity.normalize_bundle`.
    """
    payload: dict[str, Any] = json.loads(bundle.model_dump_json(exclude_none=False))
    return payload


def _subject_for_bundle(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    """Build the in-toto ``subject`` list for the wrapped bundle.

    One subject per bundle: the bundle itself, identified by its
    structural SHA-256 (the same hash ``sdlc-evidence verify`` would
    print). Using the structural hash, not the on-disk hash, means the
    Statement remains valid across cosmetic JSON re-serialisations.
    """
    structural = normalize_bundle(_bundle_payload(bundle))
    digest = hashlib.sha256(structural).hexdigest()
    subject_name = f"sdlc-evidence/{bundle.application.repository}@{bundle.release.release_id}"
    return [
        {
            "name": subject_name,
            "digest": {"sha256": digest},
        }
    ]


def build_statement(
    bundle: EvidenceBundle,
    *,
    predicate_type: PredicateType = "evidence-bundle",
) -> dict[str, Any]:
    """Return an in-toto Statement v1 dict that wraps ``bundle``.

    The ``predicate_type`` parameter selects which predicateType URI is
    advertised:

    * ``evidence-bundle`` (default) — project-native predicate type
      (``…/predicate/sdlc-evidence/v1``). Use when the consumer expects
      raw Secure SDLC evidence semantics.
    * ``witness`` — Witness-compatible custom attestation. The bundle
      payload travels as the predicate body so Witness verifiers can
      consume it without bespoke parsers.
    * ``slsa-provenance`` — advertised as ``https://slsa.dev/provenance/v1``
      for tooling that gates on the SLSA predicate type (GUAC,
      slsa-verifier, policy-controller). Consumers should still rely on
      the bundle's own ``release`` block for build metadata.

    The output is plain JSON-serialisable types so callers can write
    it to disk with ``json.dumps`` and feed it directly to ``cosign
    attest --predicate <file>``.
    """
    return {
        "_type": IN_TOTO_TYPE,
        "predicateType": predicate_type_url(predicate_type),
        "subject": _subject_for_bundle(bundle),
        "predicate": _bundle_payload(bundle),
    }


def build_dsse_envelope(statement: dict[str, Any]) -> dict[str, Any]:
    """Return an unsigned DSSE envelope wrapping ``statement``.

    The envelope is shaped to match what ``cosign sign-blob`` consumes
    as a pre-signed input. Signatures are intentionally empty: signing
    is the deployer's responsibility, not the collector's.
    """
    payload_bytes = json.dumps(statement, sort_keys=True).encode("utf-8")
    payload_b64 = base64.standard_b64encode(payload_bytes).decode("ascii")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": [],
    }
