"""T6.8 / T6.9 — Unit tests for regulatory profiles and the GUAC adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from evidence_collector.application.profiles import (
    CRA_DISCLOSURE_WINDOW,
    CRA_FINAL_REPORT_WINDOW,
    CRA_FULL_NOTIFICATION_WINDOW,
    FEDRAMP_RULESET_VERSION,
    CraReportingContext,
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
    RawEvidenceRef,
    ReleaseContext,
    Summary,
    TopRiskCve,
    VulnerabilityIntelligence,
)
from evidence_collector.exporters.guac import GUAC_DOCUMENT_TYPES, build_guac_collection


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
    evidence_id: str = "sca-1",
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
        evidence_id=evidence_id,
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
    context = CraReportingContext(
        release_id=bundle.release.release_id,
        commit_sha=bundle.release.commit_sha,
        notification_type="vulnerability",
        awareness_at=fixed_now,
    )
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026, cra_context=context)
    cra = annotated.evidence[0].metadata["cra"]
    expected = (fixed_now + CRA_DISCLOSURE_WINDOW).isoformat()
    assert cra["disclosure_deadline"] == expected
    assert cra["regulation"] == "EU CRA 2024/2847"


def test_cra_profile_emits_full_reporting_timeline() -> None:
    fixed_now = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
    bundle = _bundle([_evidence()])
    context = CraReportingContext(
        release_id=bundle.release.release_id,
        commit_sha=bundle.release.commit_sha,
        notification_type="vulnerability",
        awareness_at=fixed_now,
    )
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026, cra_context=context)
    deadlines = annotated.evidence[0].metadata["cra"]["reporting_deadlines"]
    assert deadlines["early_warning"] == (fixed_now + CRA_DISCLOSURE_WINDOW).isoformat()
    assert deadlines["full_notification"] == (fixed_now + CRA_FULL_NOTIFICATION_WINDOW).isoformat()
    # The final report is relative to remediation availability, not the anchor.
    assert deadlines["final_report"] == {
        "relative_to": "corrective_or_mitigating_measure_available",
        "window_days": CRA_FINAL_REPORT_WINDOW.days,
    }
    assert annotated.evidence[0].metadata["cra"]["reporting_obligation_start"] == "2026-09-11"


def test_cra_profile_records_global_kev_without_product_exploitation_claim() -> None:
    bundle = _bundle([_evidence(in_kev=True, known_ransomware=True)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "not_assessed"
    assert annotated.evidence[0].metadata["cra"]["global_exploitation_signal"] == "kev_listed"


def test_cra_profile_records_high_epss_as_a_tool_signal() -> None:
    bundle = _bundle([_evidence(epss_percentile=0.95)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "not_assessed"
    assert (
        annotated.evidence[0].metadata["cra"]["global_exploitation_signal"]
        == "high_epss_percentile"
    )


def test_cra_profile_defaults_to_under_investigation() -> None:
    bundle = _bundle([_evidence(epss_percentile=0.1)])
    annotated = apply_profile(bundle, ReleaseProfile.CRA_2026)
    assert annotated.evidence[0].metadata["cra"]["exploitation_status"] == "not_assessed"


# ---------- FedRAMP profile ----------


def test_fedramp_profile_records_the_ruleset() -> None:
    bundle = _bundle([_evidence()])
    annotated = apply_profile(bundle, ReleaseProfile.FEDRAMP_20X)
    fedramp = annotated.evidence[0].metadata["fedramp"]
    assert fedramp["ruleset_version"] == FEDRAMP_RULESET_VERSION
    assert "retention_years" not in fedramp
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
    sbom = _sourced(
        EvidenceType.SBOM, "sbom", content_type="application/vnd.cyclonedx+json"
    ).model_copy(update={"evidence_id": "sbom-1"})
    bundle = _bundle([sbom, _evidence()])
    doc = build_guac_collection(bundle)
    assert doc["format"] == "guac-collect"
    assert doc["release"]["release_id"] == "2026.05.19"
    assert len(doc["documents"]) == 2
    # The second record is a Trivy JSON SCA scan: JSON, not SARIF.
    assert [d["type"] for d in doc["documents"]] == ["sbom", "evidence"]


def test_guac_adapter_falls_back_to_evidence_for_unknown_type() -> None:
    bundle = _bundle([_evidence(evidence_type=EvidenceType.RELEASE_APPROVAL)])
    doc = build_guac_collection(bundle)
    assert doc["documents"][0]["type"] == "evidence"


def _sourced(
    evidence_type: EvidenceType,
    kind: str,
    *,
    content_type: str | None = None,
    artifact_path: str = "artifacts/input.json",
) -> NormalizedEvidence:
    return _evidence(evidence_type=evidence_type).model_copy(
        update={
            "source": EvidenceSource(name="tool", kind=kind),
            "raw": RawEvidenceRef(content_type=content_type, artifact_path=artifact_path),
        }
    )


@pytest.mark.parametrize(
    ("evidence_type", "kind", "content_type", "expected"),
    [
        (EvidenceType.SBOM, "sbom", "application/vnd.cyclonedx+json", "sbom"),
        (EvidenceType.SBOM, "sbom", "application/spdx+json", "sbom"),
        (EvidenceType.SAST_SCAN, "sarif", "application/sarif+json", "sarif"),
        (EvidenceType.SCA_SCAN, "sarif", "application/sarif+json", "sarif"),
        # ZAP, Trivy and OSV-Scanner write their own JSON, not SARIF.
        (EvidenceType.DAST_SCAN, "dast", "application/json", "evidence"),
        (EvidenceType.SCA_SCAN, "sca", "application/json", "evidence"),
        (EvidenceType.SECRETS_SCAN, "secrets", "application/json", "evidence"),
        # in-toto Statements, bare or wrapped in DSSE / a Sigstore bundle.
        (EvidenceType.ARTIFACT_ATTESTATION, "slsa-provenance", "application/json", "attestation"),
        (EvidenceType.ARTIFACT_ATTESTATION, "slsa-vsa", "application/json", "attestation"),
        (
            EvidenceType.ARTIFACT_ATTESTATION,
            "release-attestation",
            "application/json",
            "attestation",
        ),
        (EvidenceType.SCA_SCAN, "in-toto-vulns", "application/json", "attestation"),
        # PyPI Integrity API objects and npm/GitHub attestations[] responses
        # wrap the statements in a registry shape GUAC does not read.
        (EvidenceType.ARTIFACT_ATTESTATION, "registry-attestation", "application/json", "evidence"),
        # The collector's own attestation file (YAML or JSON) is not in-toto.
        (EvidenceType.GENERIC_ATTESTATION, "attestation", "application/yaml", "evidence"),
        (EvidenceType.ARTIFACT_SIGNATURE, "attestation", "application/json", "evidence"),
    ],
)
def test_guac_document_type_follows_the_file_format(
    evidence_type: EvidenceType, kind: str, content_type: str, expected: str
) -> None:
    evidence = _sourced(evidence_type, kind, content_type=content_type)
    doc = build_guac_collection(_bundle([evidence]))
    assert doc["documents"][0]["type"] == expected


def test_guac_artifact_path_uses_posix_separators() -> None:
    evidence = _sourced(
        EvidenceType.DAST_SCAN,
        "dast",
        content_type="application/json",
        artifact_path="examples\\sample_release\\artifacts\\zap-baseline.json",
    )
    doc = build_guac_collection(_bundle([evidence]))
    assert (
        doc["documents"][0]["artifact_path"]
        == "examples/sample_release/artifacts/zap-baseline.json"
    )


def test_guac_docs_list_exactly_the_document_types_the_exporter_emits() -> None:
    docs = (Path(__file__).resolve().parents[2] / "docs" / "guac.md").read_text(encoding="utf-8")
    listed = " / ".join(f"`{t}`" for t in GUAC_DOCUMENT_TYPES)
    assert f"({listed})" in docs
    assert "`vex`" not in docs
    # GUAC's file collector does not read this container; the docs must not
    # tell users to feed it to `guacone collect files` directly.
    assert "guacone collect files /path/to/output/sample_release/guac-collection.json" not in docs
