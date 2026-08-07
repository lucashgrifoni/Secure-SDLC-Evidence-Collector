"""Unit tests for the in-toto Statement exporter."""

from __future__ import annotations

import base64
import hashlib
import json

from evidence_collector import __version__
from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.intoto import (
    IN_TOTO_TYPE,
    PREDICATE_TYPE,
    PREDICATE_TYPE_NAMES,
    PREDICATE_TYPE_SLSA_PROVENANCE,
    PREDICATE_TYPE_SVR,
    PREDICATE_TYPE_WITNESS,
    SVR_PROPERTY_RELEASE_READY,
    VERIFIER_ID_BASE,
    build_dsse_envelope,
    build_statement,
)


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-intoto-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.18", commit_sha="abcdef1234567890"),
        evidence=[
            NormalizedEvidence(
                evidence_id="sca-1",
                evidence_type=EvidenceType.SCA_SCAN,
                source=EvidenceSource(name="trivy", kind="sarif"),
                producer="trivy",
                subject_type=SubjectType.COMMIT,
                subject_ref="abcdef1234567890",
                status=EvidenceStatus.GENERATED,
                confidence=ConfidenceLevel.HIGH,
                release_id="2026.05.18",
                commit_sha="abcdef1234567890",
                cve_ids=["CVE-2024-1111"],
            )
        ],
        control_evaluations=[],
        gaps=[],
        exceptions=[],
        summary=Summary(
            total_controls=0,
            controls_met=0,
            controls_partial=0,
            controls_missing=0,
            controls_waived=0,
            controls_not_applicable=0,
            release_status=ReleaseStatus.READY,
            evidence_coverage_score=0,
            confidence_score=0,
        ),
    )


def test_build_statement_shape_matches_in_toto_v1() -> None:
    stmt = build_statement(_bundle())
    assert stmt["_type"] == IN_TOTO_TYPE
    assert stmt["predicateType"] == PREDICATE_TYPE
    assert isinstance(stmt["subject"], list) and len(stmt["subject"]) == 1
    assert isinstance(stmt["predicate"], dict)
    assert stmt["predicate"]["bundle_id"] == "bundle-intoto-test"


def test_subject_digest_matches_structural_sha256() -> None:
    bundle = _bundle()
    stmt = build_statement(bundle)
    subject = stmt["subject"][0]
    assert subject["name"] == "sdlc-evidence/acme/api@2026.05.18"
    expected = hashlib.sha256(
        normalize_bundle(json.loads(bundle.model_dump_json(exclude_none=False)))
    ).hexdigest()
    assert subject["digest"]["sha256"] == expected


def test_build_statement_is_idempotent_for_same_bundle() -> None:
    bundle = _bundle()
    first = build_statement(bundle)
    second = build_statement(bundle)
    assert first["subject"] == second["subject"]
    assert first["predicateType"] == second["predicateType"]


def test_dsse_envelope_payload_decodes_to_statement() -> None:
    stmt = build_statement(_bundle())
    envelope = build_dsse_envelope(stmt)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert envelope["signatures"] == []
    decoded = json.loads(base64.standard_b64decode(envelope["payload"]).decode("utf-8"))
    assert decoded["_type"] == IN_TOTO_TYPE
    assert decoded["predicateType"] == PREDICATE_TYPE


def test_statement_predicate_preserves_full_bundle() -> None:
    bundle = _bundle()
    stmt = build_statement(bundle)
    assert stmt["predicate"]["application"]["name"] == "acme-api"
    assert stmt["predicate"]["evidence"][0]["evidence_id"] == "sca-1"
    assert stmt["predicate"]["evidence"][0]["cve_ids"] == ["CVE-2024-1111"]


def test_build_statement_default_is_evidence_bundle_predicate() -> None:
    """Default behaviour must match the pre-T6.3 contract for backward-compat."""
    stmt = build_statement(_bundle())
    assert stmt["predicateType"] == PREDICATE_TYPE


def test_build_statement_witness_predicate_advertises_witness_uri() -> None:
    stmt = build_statement(_bundle(), predicate_type="witness")
    assert stmt["predicateType"] == PREDICATE_TYPE_WITNESS
    # Same subject digest as default: the bundle bytes did not change.
    assert stmt["subject"] == build_statement(_bundle())["subject"]


def test_build_statement_slsa_provenance_predicate_uses_slsa_uri() -> None:
    stmt = build_statement(_bundle(), predicate_type="slsa-provenance")
    assert stmt["predicateType"] == PREDICATE_TYPE_SLSA_PROVENANCE


def test_build_statement_round_trip_through_dsse_preserves_predicate_type() -> None:
    """A Witness Statement must survive DSSE base64 round-trip."""
    stmt = build_statement(_bundle(), predicate_type="witness")
    envelope = build_dsse_envelope(stmt)
    decoded = json.loads(base64.standard_b64decode(envelope["payload"]).decode("utf-8"))
    assert decoded["predicateType"] == PREDICATE_TYPE_WITNESS


# ---------------------------------------------------------------------------
# SVR (Simple Verification Result) v0.2
# ---------------------------------------------------------------------------


def _evaluation(
    control_id: str,
    status: ControlEvaluationStatus,
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=ControlFramework.NIST_SSDF,
        control_name=f"Control {control_id}",
        evaluation_status=status,
        criticality=ControlCriticality.HIGH,
        rationale="fixture",
    )


def _svr_bundle(release_status: ReleaseStatus = ReleaseStatus.READY) -> EvidenceBundle:
    """A bundle carrying one control of every evaluation status."""
    bundle = _bundle()
    bundle.control_evaluations = [
        _evaluation("SSDF-PS.3", ControlEvaluationStatus.MET),
        _evaluation("SSDF-PO.3", ControlEvaluationStatus.PARTIAL),
        _evaluation("SSDF-PW.4", ControlEvaluationStatus.MISSING),
        _evaluation("SSDF-RV.1", ControlEvaluationStatus.WAIVED),
        _evaluation("SSDF-PW.7", ControlEvaluationStatus.NOT_APPLICABLE),
        _evaluation("ORG-001", ControlEvaluationStatus.MET),
    ]
    bundle.summary.release_status = release_status
    return bundle


def test_svr_statement_advertises_the_svr_uri() -> None:
    stmt = build_statement(_svr_bundle(), predicate_type="svr")
    assert stmt["predicateType"] == PREDICATE_TYPE_SVR
    assert stmt["predicateType"] == "https://in-toto.io/attestation/svr/v0.2"


def test_svr_predicate_has_exactly_the_required_fields() -> None:
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    assert set(predicate) == {"verifier", "timeCreated", "properties"}
    assert set(predicate["verifier"]) == {"id", "policies"}


def test_svr_predicate_is_not_the_bundle() -> None:
    # Every other variant embeds the bundle. Advertising svr/v0.2 with a
    # bundle-shaped body would ship a predicate that fails its own schema.
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    assert "bundle_id" not in predicate
    assert "control_evaluations" not in predicate


def test_svr_properties_list_only_met_controls() -> None:
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    assert predicate["properties"] == [
        "SDLC_EVIDENCE_ORG-001_PASSED",
        "SDLC_EVIDENCE_SSDF-PS.3_PASSED",
        "SDLC_EVIDENCE_RELEASE_READY",
    ]


def test_svr_properties_exclude_partial_missing_waived_and_na() -> None:
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    joined = " ".join(predicate["properties"])
    for absent in ("SSDF-PO.3", "SSDF-PW.4", "SSDF-RV.1", "SSDF-PW.7"):
        assert absent not in joined


def test_svr_release_ready_property_tracks_the_verdict() -> None:
    for status, expected in (
        (ReleaseStatus.READY, True),
        (ReleaseStatus.CONDITIONAL, False),
        (ReleaseStatus.NOT_READY, False),
    ):
        predicate = build_statement(_svr_bundle(status), predicate_type="svr")["predicate"]
        assert (SVR_PROPERTY_RELEASE_READY in predicate["properties"]) is expected


def test_svr_time_created_comes_from_the_bundle_not_the_clock() -> None:
    # Reusing generated_at keeps the export a pure function of its input.
    bundle = _svr_bundle()
    predicate = build_statement(bundle, predicate_type="svr")["predicate"]
    assert predicate["timeCreated"].startswith(
        bundle.generated_at.isoformat().replace("+00:00", "Z")[:19]
    )


def test_svr_export_is_byte_identical_across_runs() -> None:
    bundle = _svr_bundle()
    first = json.dumps(build_statement(bundle, predicate_type="svr"), sort_keys=True)
    second = json.dumps(build_statement(bundle, predicate_type="svr"), sort_keys=True)
    assert first == second


def test_svr_policies_is_empty_rather_than_invented() -> None:
    # The spec permits an empty array. The bundle records no resolvable
    # identifier for the catalogue it was evaluated against, and a
    # ResourceDescriptor needs uri/digest/content — so anything non-empty
    # here would be fabricated.
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    assert predicate["verifier"]["policies"] == []


def test_svr_verifier_id_is_versioned() -> None:
    predicate = build_statement(_svr_bundle(), predicate_type="svr")["predicate"]
    assert predicate["verifier"]["id"] == f"{VERIFIER_ID_BASE}/v{__version__}"


def test_svr_subject_still_uses_the_structural_digest() -> None:
    bundle = _svr_bundle()
    stmt = build_statement(bundle, predicate_type="svr")
    expected = hashlib.sha256(
        normalize_bundle(json.loads(bundle.model_dump_json(exclude_none=False)))
    ).hexdigest()
    assert stmt["subject"][0]["digest"]["sha256"] == expected


def test_svr_bundle_with_no_met_controls_yields_only_the_verdict() -> None:
    bundle = _bundle()
    bundle.summary.release_status = ReleaseStatus.READY
    predicate = build_statement(bundle, predicate_type="svr")["predicate"]
    assert predicate["properties"] == [SVR_PROPERTY_RELEASE_READY]


def test_predicate_type_names_covers_every_registered_variant() -> None:
    assert set(PREDICATE_TYPE_NAMES) == {
        "evidence-bundle",
        "witness",
        "slsa-provenance",
        "svr",
    }
