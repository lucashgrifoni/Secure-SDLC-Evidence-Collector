"""T6.8 / T6.9 — Unit tests for regulatory profiles and the GUAC adapter."""

from __future__ import annotations

from datetime import UTC, datetime

from evidence_collector.application.profiles import (
    CRA_DISCLOSURE_WINDOW,
    FEDRAMP_20X_RETENTION_YEARS,
    ReleaseProfile,
    apply_profile,
)
from evidence_collector.controls.catalog import bundled_catalog_path, load_catalog
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
    TopRiskCve,
    VulnerabilityIntelligence,
)
from evidence_collector.exporters.guac import build_guac_collection


def _bundle(evidence: list[NormalizedEvidence]) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-profile-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.19", commit_sha="abcdef1234567890"),
        evidence=evidence,
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


def _evidence(
    *,
    in_kev: bool = False,
    known_ransomware: bool = False,
    epss_percentile: float = 0.1,
    evidence_type: EvidenceType = EvidenceType.SCA_SCAN,
) -> NormalizedEvidence:
    intel = VulnerabilityIntelligence(
        cve_count=1,
        cves_in_kev_count=1 if in_kev else 0,
        cves_known_ransomware_count=1 if known_ransomware else 0,
        top_risk_cves=[
            TopRiskCve(
                cve_id="CVE-2024-1111",
                epss_score=epss_percentile,
                epss_percentile=epss_percentile,
                in_kev=in_kev,
                known_ransomware=known_ransomware,
            )
        ],
    )
    return NormalizedEvidence(
        evidence_id="sca-1",
        evidence_type=evidence_type,
        source=EvidenceSource(name="trivy", kind="sca"),
        producer="trivy",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="acme/api@1.0",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        cve_ids=["CVE-2024-1111"],
        vulnerability_intelligence=intel,
    )


# ---------- CRA profile ----------


def test_cra_profile_annotates_24h_deadline() -> None:
    fixed_now = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
    bundle = _bundle([_evidence()])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026, now=fixed_now)
    cra = annotated.evidence[0].metadata["cra"]
    expected = (fixed_now + CRA_DISCLOSURE_WINDOW).isoformat()
    assert cra["disclosure_deadline"] == expected
    assert cra["regulation"] == "EU CRA 2024/2847"


def test_cra_profile_classifies_kev_ransomware_as_actively_exploited() -> None:
    bundle = _bundle([_evidence(in_kev=True, known_ransomware=True)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "actively_exploited"


def test_cra_profile_classifies_high_epss_as_known_exploitable() -> None:
    bundle = _bundle([_evidence(epss_percentile=0.95)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "known_exploitable"


def test_cra_profile_defaults_to_under_investigation() -> None:
    bundle = _bundle([_evidence(epss_percentile=0.1)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "under_investigation"


# ---------- FedRAMP profile ----------


def test_fedramp_profile_stamps_retention() -> None:
    bundle = _bundle([_evidence()])
    annotated = apply_profile(bundle, ReleaseProfile.FEDRAMP_20X)
    fedramp = annotated.evidence[0].metadata["fedramp"]
    assert fedramp["retention_years"] == FEDRAMP_20X_RETENTION_YEARS
    assert fedramp["profile"] == "20x"


def test_none_profile_returns_bundle_unchanged() -> None:
    bundle = _bundle([_evidence()])
    out = apply_profile(bundle, ReleaseProfile.NONE)
    assert out is bundle


# ---------- FedRAMP KSI catalog ----------


def test_fedramp_ksi_catalog_loads_and_includes_critical_baseline() -> None:
    path = bundled_catalog_path("catalog-fedramp-20x-ksi.yaml")
    controls = {c.control_id: c for c in load_catalog(path)}
    assert "KSI-LOW-SBOM" in controls
    assert "KSI-MOD-DAST" in controls
    assert controls["KSI-LOW-SBOM"].criticality.value == "critical"


# ---------- GUAC adapter ----------


def test_guac_adapter_emits_one_document_per_evidence() -> None:
    bundle = _bundle([_evidence(evidence_type=EvidenceType.SBOM), _evidence()])
    doc = build_guac_collection(bundle)
    assert doc["format"] == "guac-collect"
    assert doc["release"]["release_id"] == "2026.05.19"
    assert len(doc["documents"]) == 2
    types = {d["type"] for d in doc["documents"]}
    assert "sbom" in types
    assert "sarif" in types


def test_guac_adapter_falls_back_to_evidence_for_unknown_type() -> None:
    bundle = _bundle([_evidence(evidence_type=EvidenceType.RELEASE_APPROVAL)])
    doc = build_guac_collection(bundle)
    assert doc["documents"][0]["type"] == "evidence"
