"""Freshness + self-description gate for the published bundle JSON Schema.

``docs/evidence-bundle.schema.json`` is committed so it can be served from a
stable URL (GitHub Pages) and mirrored to registries like SchemaStore. These
tests fail if it drifts from the model, so the published contract can never go
stale, and assert it carries the ``$schema``/``$id`` keywords editors need.
"""

from __future__ import annotations

import json
from pathlib import Path

from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import (
    BUNDLE_SCHEMA_VERSION,
    Application,
    CollectionError,
    EvidenceBundle,
    ReleaseContext,
    Summary,
)
from evidence_collector.schema import (
    BUNDLE_SCHEMA_DIALECT,
    BUNDLE_SCHEMA_ID,
    bundle_json_schema,
    bundle_json_schema_text,
)

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "docs" / "evidence-bundle.schema.json"


def test_committed_bundle_schema_is_in_sync() -> None:
    committed = _SCHEMA_PATH.read_text(encoding="utf-8")
    assert committed == bundle_json_schema_text(), (
        "docs/evidence-bundle.schema.json is stale — regenerate it with "
        "`sdlc-evidence schema --output docs/evidence-bundle.schema.json`"
    )


def test_committed_bundle_schema_is_self_describing() -> None:
    data = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert data["$id"] == BUNDLE_SCHEMA_ID
    assert data["$schema"] == BUNDLE_SCHEMA_DIALECT
    assert data["title"] == "EvidenceBundle"
    # The contract must keep its top-level shape (the bundle's fields).
    assert "control_evaluations" in data["properties"]


def test_bundle_version_tracks_the_published_contract() -> None:
    """The version field and the committed schema must agree.

    `bundle_version` exists so a consumer can tell when a bundle no longer
    matches the contract it pinned. It stayed at 1.0.0 while the bundle gained
    `collection_errors` and the published schema — `additionalProperties:
    false` at every level — started rejecting bundles that carried it. A
    version that does not move when the shape moves is worse than no version:
    the consumer gets a validation failure with no way to learn a newer schema
    exists.
    """
    schema = bundle_json_schema()
    assert schema["properties"]["bundle_version"]["default"] == BUNDLE_SCHEMA_VERSION
    # The strictness that makes an additive field breaking, and therefore
    # makes the version bump necessary.
    assert schema["additionalProperties"] is False
    assert "collection_errors" in schema["properties"]


def test_a_clean_bundle_still_validates_against_the_previous_contract(
    sample_application: Application, sample_release: ReleaseContext
) -> None:
    """No collection problems means no new field, so no new schema needed.

    Emitting `"collection_errors": []` on every run broke every consumer
    pinned to 1.0.0, including the overwhelming majority of runs where nothing
    had gone wrong. The key is omitted when empty, so those bundles carry
    exactly the members 1.0.0 knows about.
    """
    bundle = EvidenceBundle(
        bundle_id="bundle-clean",
        application=sample_application,
        release=sample_release,
        evidence=[],
        control_evaluations=[],
        summary=Summary(
            evidence_coverage_score=0,
            confidence_score=0,
            release_status=ReleaseStatus.NOT_READY,
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
        ),
    )

    payload = json.loads(bundle.model_dump_json())

    assert bundle.collection_errors == []
    assert "collection_errors" not in payload


def test_a_bundle_that_records_a_failure_carries_the_field(
    sample_application: Application, sample_release: ReleaseContext
) -> None:
    """...and when there is something to report, it is reported.

    Omitting the empty case must not turn into omitting the field. This is
    the half of the contract that carries information.
    """
    bundle = EvidenceBundle(
        bundle_id="bundle-degraded",
        application=sample_application,
        release=sample_release,
        evidence=[],
        control_evaluations=[],
        collection_errors=[CollectionError(path="artifacts/broken.json", reason="Invalid JSON")],
        summary=Summary(
            evidence_coverage_score=0,
            confidence_score=0,
            release_status=ReleaseStatus.NOT_READY,
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
        ),
    )

    payload = json.loads(bundle.model_dump_json())

    assert payload["collection_errors"] == [
        {"path": "artifacts/broken.json", "reason": "Invalid JSON"}
    ]
    # Round-trips: omitting the empty case must not break reload either.
    assert EvidenceBundle(**json.loads(bundle.model_dump_json())).collection_errors == (
        bundle.collection_errors
    )


def test_the_serialization_schema_is_the_full_contract_too() -> None:
    """Both schema modes must describe the bundle, not just the validation one.

    Pydantic builds the serialization schema from a wrap serializer's annotated
    return type. Declaring `-> dict[str, Any]` on `_omit_empty_collection_errors`
    replaced the whole contract with `{"additionalProperties": true, "type":
    "object"}` — no properties, no $defs — while validation mode stayed
    complete, so nothing in the suite noticed.

    Serialization mode is the semantically correct one for a schema describing
    *produced* bundles, and it is the mode FastAPI uses for `response_model`.
    A downstream service exposing `response_model=EvidenceBundle` therefore
    published an untyped object in its OpenAPI, from a package that ships
    `py.typed`. `-> Any` collapses it the same way, so the annotation has to
    stay absent.
    """
    validation = EvidenceBundle.model_json_schema(mode="validation")
    serialization = EvidenceBundle.model_json_schema(mode="serialization")

    for mode, schema in (("validation", validation), ("serialization", serialization)):
        assert schema.get("additionalProperties") is False, mode
        assert len(schema.get("properties", {})) == len(validation["properties"]), mode
        assert schema.get("$defs"), mode
    assert "collection_errors" in serialization["properties"]
