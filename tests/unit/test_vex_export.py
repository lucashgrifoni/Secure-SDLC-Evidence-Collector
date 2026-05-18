"""Unit tests for the OpenVEX exporter.

The exporter is pure: given a bundle and an optional fixed clock, it
returns a deterministic ``dict``. Tests assert structure and the three
status-decision branches (under_investigation → affected → not_affected).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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
    EvidenceException,
    EvidenceSource,
    NormalizedEvidence,
    ReleaseContext,
    Summary,
    TopRiskCve,
    VulnerabilityIntelligence,
)
from evidence_collector.exporters.vex import (
    STATUS_AFFECTED,
    STATUS_NOT_AFFECTED,
    STATUS_UNDER_INVESTIGATION,
    build_openvex,
)


def _evidence(
    cve_ids: list[str],
    *,
    evidence_id: str = "sca-1",
    top_risk: list[TopRiskCve] | None = None,
) -> NormalizedEvidence:
    intel = None
    if top_risk is not None:
        intel = VulnerabilityIntelligence(
            cve_count=len(cve_ids),
            cves_in_kev_count=sum(1 for t in top_risk if t.in_kev),
            cves_known_ransomware_count=sum(1 for t in top_risk if t.known_ransomware),
            top_risk_cves=top_risk,
        )
    return NormalizedEvidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name="trivy", kind="sarif"),
        producer="trivy",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567890",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.18",
        commit_sha="abcdef1234567890",
        cve_ids=cve_ids,
        vulnerability_intelligence=intel,
    )


def _bundle(
    evidence: list[NormalizedEvidence],
    exceptions: list[EvidenceException] | None = None,
) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-vex-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.18", commit_sha="abcdef1234567890"),
        evidence=evidence,
        control_evaluations=[],
        gaps=[],
        exceptions=exceptions or [],
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


def test_build_openvex_default_status_is_under_investigation() -> None:
    bundle = _bundle([_evidence(["CVE-2024-1111"])])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))

    assert doc["@context"].startswith("https://openvex.dev/ns/")
    assert doc["version"] == 1
    assert doc["author"] == "secure-sdlc-evidence-collector"
    assert doc["@id"].startswith("https://openvex.dev/docs/")
    assert len(doc["statements"]) == 1
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_UNDER_INVESTIGATION
    assert statement["vulnerability"]["name"] == "CVE-2024-1111"
    assert statement["products"][0]["@id"] == "pkg:generic/acme/api@2026.05.18"


def test_build_openvex_marks_kev_cves_as_affected() -> None:
    top = [
        TopRiskCve(
            cve_id="CVE-2024-2222",
            epss_score=0.95,
            epss_percentile=0.99,
            in_kev=True,
            known_ransomware=True,
        )
    ]
    bundle = _bundle([_evidence(["CVE-2024-2222"], top_risk=top)])

    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_AFFECTED
    assert "CISA KEV" in statement["action_statement"]


def test_build_openvex_marks_waived_cves_as_not_affected() -> None:
    now = datetime(2026, 5, 18, tzinfo=UTC)
    waiver = EvidenceException(
        exception_id="EX-001",
        control_id="SSDF-PW.4",
        approver="security-team",
        approved_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=30),
        justification="Library is loaded but the affected function is never called.",
        reference="JIRA-1234",
    )
    bundle = _bundle([_evidence(["CVE-2024-3333"])], exceptions=[waiver])

    doc = build_openvex(bundle, now=now)
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_NOT_AFFECTED
    assert "EX-001" in statement["status_notes"]
    assert statement["impact_statement"] == waiver.justification


def test_build_openvex_is_deterministic_for_same_inputs() -> None:
    bundle = _bundle([_evidence(["CVE-2024-4444", "CVE-2024-5555"])])
    fixed_now = datetime(2026, 5, 18, 12, tzinfo=UTC)
    first = build_openvex(bundle, now=fixed_now)
    second = build_openvex(bundle, now=fixed_now)
    assert first["@id"] == second["@id"]
    assert first["statements"] == second["statements"]


def test_build_openvex_sorts_statements_by_cve_id() -> None:
    bundle = _bundle(
        [
            _evidence(["CVE-2024-9999"], evidence_id="e1"),
            _evidence(["CVE-2024-1111"], evidence_id="e2"),
            _evidence(["CVE-2024-5555"], evidence_id="e3"),
        ]
    )
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    cve_ids = [s["vulnerability"]["name"] for s in doc["statements"]]
    assert cve_ids == sorted(cve_ids)


def test_build_openvex_emits_empty_statements_for_bundle_without_cves() -> None:
    bundle = _bundle([_evidence([])])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    assert doc["statements"] == []


def test_build_openvex_handles_missing_repository() -> None:
    bundle = _bundle([_evidence(["CVE-2024-7777"])])
    bundle = bundle.model_copy(
        update={
            "application": Application(name="acme-api", repository="x"),
        }
    )
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    assert doc["statements"][0]["products"][0]["@id"].startswith("pkg:generic/x")


@pytest.mark.parametrize(
    "cve_input,expected",
    [
        (["cve-2024-1111"], "CVE-2024-1111"),
        (["CVE-2024-1111", "cve-2024-1111"], "CVE-2024-1111"),
    ],
)
def test_build_openvex_normalises_cve_casing_and_deduplicates(
    cve_input: list[str], expected: str
) -> None:
    bundle = _bundle([_evidence(cve_input)])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    names = [s["vulnerability"]["name"] for s in doc["statements"]]
    assert names == [expected]
