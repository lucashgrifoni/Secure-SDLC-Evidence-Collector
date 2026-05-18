"""Unit tests for the in-toto Statement exporter."""

from __future__ import annotations

import base64
import hashlib
import json

from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    EvidenceBundle,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.intoto import (
    IN_TOTO_TYPE,
    PREDICATE_TYPE,
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
