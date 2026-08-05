"""T6.6 — Unit tests for the risk-weighted verdict (epss-weighted mode).

Verifies precedence:
* KEV with ransomware  → NOT_READY (overrides base)
* Any exploitable      → at least CONDITIONAL (worse-of base, conditional)
* Otherwise            → base verdict preserved
* Reachability == not_reachable suppresses the signal for that evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime

from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceSource,
    NormalizedEvidence,
    Reachability,
    Summary,
    TopRiskCve,
    VulnerabilityIntelligence,
)
from evidence_collector.scoring import (
    DEFAULT_EPSS_PERCENTILE_THRESHOLD,
    RiskMode,
    RiskThresholds,
    apply_risk_mode,
)


def _summary(status: ReleaseStatus) -> Summary:
    return Summary(
        evidence_coverage_score=80,
        confidence_score=80,
        release_status=status,
        total_controls=1,
        controls_met=1,
        controls_partial=0,
        controls_missing=0,
        controls_waived=0,
        controls_not_applicable=0,
    )


def _evidence(
    top_risk: list[TopRiskCve],
    *,
    reachability: Reachability | None = None,
) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id="sca-1",
        evidence_type=EvidenceType.SCA_SCAN,
        source=EvidenceSource(name="trivy", kind="sca"),
        producer="trivy",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="acme/api@1.0",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        cve_ids=[t.cve_id for t in top_risk],
        vulnerability_intelligence=VulnerabilityIntelligence(
            cve_count=len(top_risk),
            cves_in_kev_count=sum(1 for t in top_risk if t.in_kev),
            cves_known_ransomware_count=sum(1 for t in top_risk if t.known_ransomware),
            top_risk_cves=top_risk,
            enriched_at=datetime(2026, 5, 19, tzinfo=UTC),
        ),
        reachability=reachability,
    )


def test_off_mode_returns_summary_unchanged() -> None:
    summary = _summary(ReleaseStatus.READY)
    out = apply_risk_mode(summary, [], mode=RiskMode.OFF)
    assert out is summary
    assert out.risk_assessment is None


def test_no_intelligence_preserves_base_verdict_and_says_so() -> None:
    """No enrichment at all ⇒ base verdict kept, and the rationale admits it.

    This used to assert ``"No exploitable" in rationale``. That wording was the
    fail-open: it reads as "the EPSS/KEV thresholds were applied and nothing
    matched", when in fact no feed was ever consulted. A missing, unreadable, or
    never-supplied feed all landed here and produced a bundle asserting the
    release had no exploitable CVEs. The verdict behaviour (base preserved) is
    unchanged — only the claim is now honest.
    """
    summary = _summary(ReleaseStatus.READY)
    out = apply_risk_mode(summary, [], mode=RiskMode.EPSS_WEIGHTED)
    assert out.release_status == ReleaseStatus.READY
    assert out.risk_assessment is not None
    assert out.risk_assessment.exploitable_cve_count == 0
    assert "no vulnerability intelligence" in out.risk_assessment.rationale
    # The claim that no exploitable CVE exists must NOT be made here.
    assert "No exploitable CVEs detected" not in out.risk_assessment.rationale


def test_enriched_evidence_without_exploitable_cves_reports_a_clean_assessment() -> None:
    """Enrichment present and nothing over threshold ⇒ the clean claim is earned."""
    summary = _summary(ReleaseStatus.READY)
    benign = TopRiskCve(
        cve_id="CVE-2024-0001",
        epss_score=0.0001,
        epss_percentile=0.01,
        in_kev=False,
        known_ransomware=False,
    )
    out = apply_risk_mode(summary, [_evidence([benign])], mode=RiskMode.EPSS_WEIGHTED)
    assert out.release_status == ReleaseStatus.READY
    assert out.risk_assessment is not None
    assert out.risk_assessment.exploitable_cve_count == 0
    assert "No exploitable CVEs detected" in out.risk_assessment.rationale
    assert "1 enriched evidence record(s) assessed" in out.risk_assessment.rationale


def test_kev_with_ransomware_forces_not_ready() -> None:
    """A KEV + ransomware CVE blocks the release regardless of base verdict."""
    summary = _summary(ReleaseStatus.READY)
    top = TopRiskCve(
        cve_id="CVE-2024-9999",
        epss_score=0.1,
        epss_percentile=0.1,
        in_kev=True,
        known_ransomware=True,
    )
    out = apply_risk_mode(summary, [_evidence([top])], mode=RiskMode.EPSS_WEIGHTED)
    assert out.release_status == ReleaseStatus.NOT_READY
    assert out.risk_assessment is not None
    assert out.risk_assessment.kev_ransomware_cve_count == 1


def test_high_epss_downgrades_to_conditional() -> None:
    """A non-KEV CVE with EPSS >= threshold forces at-least CONDITIONAL."""
    summary = _summary(ReleaseStatus.READY)
    top = TopRiskCve(
        cve_id="CVE-2024-1111",
        epss_score=0.85,
        epss_percentile=0.95,
        in_kev=False,
        known_ransomware=False,
    )
    out = apply_risk_mode(summary, [_evidence([top])], mode=RiskMode.EPSS_WEIGHTED)
    assert out.release_status == ReleaseStatus.CONDITIONAL
    assert out.risk_assessment is not None
    assert out.risk_assessment.high_epss_cve_count == 1
    assert out.risk_assessment.exploitable_cve_count == 1


def test_base_not_ready_stays_not_ready_even_when_no_exploitable_cve() -> None:
    """Risk-weighted mode does not UPGRADE the verdict — only downgrades."""
    summary = _summary(ReleaseStatus.NOT_READY)
    out = apply_risk_mode(summary, [], mode=RiskMode.EPSS_WEIGHTED)
    assert out.release_status == ReleaseStatus.NOT_READY


def test_not_reachable_evidence_suppresses_signal() -> None:
    """Reachability == not_reachable removes that evidence's CVEs from the count."""
    summary = _summary(ReleaseStatus.READY)
    top = TopRiskCve(
        cve_id="CVE-2024-1111",
        epss_score=0.99,
        epss_percentile=0.99,
        in_kev=True,
        known_ransomware=False,
    )
    reach = Reachability(
        status="not_reachable",
        source="codeql",
        method="data_flow",
    )
    out = apply_risk_mode(
        summary,
        [_evidence([top], reachability=reach)],
        mode=RiskMode.EPSS_WEIGHTED,
    )
    assert out.release_status == ReleaseStatus.READY
    assert out.risk_assessment is not None
    assert out.risk_assessment.exploitable_cve_count == 0


def test_default_threshold_is_70th_percentile() -> None:
    assert DEFAULT_EPSS_PERCENTILE_THRESHOLD == 0.7


def test_threshold_override_changes_classification() -> None:
    """A CVE at 50th percentile is NOT exploitable at 0.7, IS at 0.4."""
    summary = _summary(ReleaseStatus.READY)
    top = TopRiskCve(
        cve_id="CVE-2024-2222",
        epss_score=0.5,
        epss_percentile=0.5,
        in_kev=False,
        known_ransomware=False,
    )
    relaxed = apply_risk_mode(
        summary,
        [_evidence([top])],
        mode=RiskMode.EPSS_WEIGHTED,
        thresholds=RiskThresholds(epss_percentile_threshold=0.7),
    )
    strict = apply_risk_mode(
        summary,
        [_evidence([top])],
        mode=RiskMode.EPSS_WEIGHTED,
        thresholds=RiskThresholds(epss_percentile_threshold=0.4),
    )
    assert relaxed.release_status == ReleaseStatus.READY
    assert strict.release_status == ReleaseStatus.CONDITIONAL
