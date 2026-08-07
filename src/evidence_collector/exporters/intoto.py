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

from evidence_collector import __version__
from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.domain.enums import ControlEvaluationStatus, ReleaseStatus
from evidence_collector.domain.models import EvidenceBundle

IN_TOTO_TYPE = "https://in-toto.io/Statement/v1"

# Identity this collector claims when it acts as an in-toto *verifier*
# rather than as an evidence carrier. Versioned per the SVR spec's
# recommendation, so a consumer can tell which release produced a result.
VERIFIER_ID_BASE = "https://github.com/lucashgrifoni/secure-sdlc-evidence-collector"

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

# SVR (Simple Verification Result) variant. in-toto vetted this predicate
# for exactly what this project produces: "evidence that an artifact has
# been evaluated against one or more policies". Unlike the three variants
# above, an SVR Statement does NOT carry the bundle as its predicate — it
# carries a real SVR predicate (see ``_svr_predicate``). Advertising
# ``svr/v0.2`` while shipping a bundle-shaped body would hand a consumer a
# predicate that fails its own schema, which is the opposite of the
# guarantee this project sells.
PREDICATE_TYPE_SVR = "https://in-toto.io/attestation/svr/v0.2"

PredicateType = Literal["evidence-bundle", "witness", "slsa-provenance", "svr"]

_PREDICATE_TYPE_BY_NAME: dict[PredicateType, str] = {
    "evidence-bundle": PREDICATE_TYPE_EVIDENCE_BUNDLE,
    "witness": PREDICATE_TYPE_WITNESS,
    "slsa-provenance": PREDICATE_TYPE_SLSA_PROVENANCE,
    "svr": PREDICATE_TYPE_SVR,
}

# Prefix for the strings in the SVR ``properties`` array. The spec has no
# enum for these: it says they SHOULD be scoped by the framework or the
# verifier's policy rules (its own examples use `AMPEL_`, `CONFORMA_`,
# `SLSA_`). This is our scope.
SVR_PROPERTY_PREFIX = "SDLC_EVIDENCE_"

# Emitted alongside the per-control properties when the bundle's own
# verdict is `ready`. It is the single property a deployment gate is most
# likely to want, and deriving it downstream would mean re-implementing
# the criticality rules the collector already applied.
SVR_PROPERTY_RELEASE_READY = f"{SVR_PROPERTY_PREFIX}RELEASE_READY"


# Single source of truth for the accepted ``--predicate-type`` values. The
# CLI validates against this rather than repeating the list, so a new
# variant cannot be registered here and stay silently unreachable there.
PREDICATE_TYPE_NAMES: tuple[str, ...] = tuple(_PREDICATE_TYPE_BY_NAME)


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


def _svr_predicate(bundle: EvidenceBundle) -> dict[str, Any]:
    """Return an SVR v0.2 predicate summarising this bundle's verdict.

    Per https://in-toto.io/attestation/svr/v0.2 the predicate carries
    exactly three required fields — ``verifier`` (with ``id`` and
    ``policies``), ``timeCreated``, and ``properties``.

    ``properties`` lists what *passed*: one entry per control the bundle
    evaluated as MET, plus ``SDLC_EVIDENCE_RELEASE_READY`` when the
    bundle's own verdict is `ready`. Controls that are partial, missing,
    waived, or not-applicable are deliberately absent — SVR states
    verified properties, so "not listed" must mean "not asserted" rather
    than "asserted as failing".

    ``timeCreated`` reuses the bundle's ``generated_at`` rather than the
    wall clock, so the Statement stays a pure function of its input and
    re-running the export on the same bundle is byte-identical.

    ``policies`` is an empty array, which the spec explicitly permits. A
    ResourceDescriptor needs at least one of ``uri``, ``digest`` or
    ``content``, and the bundle does not record a resolvable identifier
    for the control catalogue it was evaluated against. Emitting a
    plausible-looking URI we never read would be fabricated provenance.
    """
    properties = sorted(
        f"{SVR_PROPERTY_PREFIX}{evaluation.control_id}_PASSED"
        for evaluation in bundle.control_evaluations
        if evaluation.evaluation_status is ControlEvaluationStatus.MET
    )
    if bundle.summary.release_status is ReleaseStatus.READY:
        properties.append(SVR_PROPERTY_RELEASE_READY)
    return {
        "verifier": {
            "id": f"{VERIFIER_ID_BASE}/v{__version__}",
            "policies": [],
        },
        "timeCreated": bundle.generated_at.isoformat().replace("+00:00", "Z"),
        "properties": properties,
    }


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
    * ``svr`` — in-toto SVR v0.2. **The only variant whose predicate is
      not the bundle**: it emits a real SVR body summarising which
      controls passed. Use it where a policy engine gates on verified
      properties rather than on raw evidence. The bundle itself is not
      carried, so a consumer who needs the underlying evidence should
      take one of the other three variants (or the bundle) as well.

    The output is plain JSON-serialisable types so callers can write
    it to disk with ``json.dumps`` and feed it directly to ``cosign
    attest --predicate <file>``.
    """
    predicate = _svr_predicate(bundle) if predicate_type == "svr" else _bundle_payload(bundle)
    return {
        "_type": IN_TOTO_TYPE,
        "predicateType": predicate_type_url(predicate_type),
        "subject": _subject_for_bundle(bundle),
        "predicate": predicate,
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
