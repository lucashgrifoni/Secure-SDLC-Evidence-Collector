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


def _sbom_evidence_with_inline_analyses(
    inline_analyses: list[dict[str, object]],
    *,
    cve_ids: list[str],
    evidence_id: str = "sbom-1",
) -> NormalizedEvidence:
    """Build an SBOM evidence that carries CycloneDX inline VEX analyses.

    Mirrors what ``normalize_sbom`` produces when the parser extracts
    ``vulnerabilities[*].analysis`` from a CycloneDX 1.4+ SBOM.
    """
    return NormalizedEvidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.SBOM,
        source=EvidenceSource(name="cyclonedx", kind="sbom", version="1.7"),
        producer="cyclonedx",
        subject_type=SubjectType.ARTIFACT,
        subject_ref="pkg:generic/acme/api@2026.05.18",
        status=EvidenceStatus.GENERATED,
        confidence=ConfidenceLevel.HIGH,
        release_id="2026.05.18",
        commit_sha="abcdef1234567890",
        cve_ids=cve_ids,
        metadata={"sbom_vex_analyses": inline_analyses},
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


def test_build_openvex_honours_inline_cyclonedx_not_affected() -> None:
    """CycloneDX inline ``not_affected`` overrides the default ``under_investigation``.

    Justification translates from CycloneDX vocabulary to OpenVEX
    (``code_not_reachable`` → ``vulnerable_code_not_in_execute_path``).
    """
    sbom = _sbom_evidence_with_inline_analyses(
        [
            {
                "cve_id": "CVE-2024-8000",
                "state": "not_affected",
                "justification": "code_not_reachable",
                "responses": ["will_not_fix"],
                "detail": "Vulnerable code path is dead.",
            }
        ],
        cve_ids=["CVE-2024-8000"],
    )
    bundle = _bundle([sbom])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_NOT_AFFECTED
    assert statement["justification"] == "vulnerable_code_not_in_execute_path"
    assert "state=not_affected" in statement["status_notes"]
    assert "Vulnerable code path is dead." in statement["status_notes"]


def test_build_openvex_inline_exploitable_beats_kev_default() -> None:
    """Inline ``exploitable`` is honoured even when the CVE is also in KEV."""
    sbom = _sbom_evidence_with_inline_analyses(
        [{"cve_id": "CVE-2024-8001", "state": "exploitable", "detail": "Triggered."}],
        cve_ids=["CVE-2024-8001"],
        evidence_id="sbom-2",
    )
    sca = _evidence(
        ["CVE-2024-8001"],
        evidence_id="sca-1",
        top_risk=[
            TopRiskCve(
                cve_id="CVE-2024-8001",
                epss_score=0.9,
                epss_percentile=0.95,
                in_kev=True,
                known_ransomware=True,
            )
        ],
    )
    bundle = _bundle([sbom, sca])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_AFFECTED
    # Inline ``exploitable`` uses our action_statement, not the KEV one.
    assert "CycloneDX inline analysis" in statement["action_statement"]


def test_build_openvex_waiver_still_wins_over_inline_analysis() -> None:
    """Explicit waiver must beat even an inline ``exploitable`` analysis."""
    now = datetime(2026, 5, 18, tzinfo=UTC)
    sbom = _sbom_evidence_with_inline_analyses(
        [{"cve_id": "CVE-2024-8002", "state": "exploitable"}],
        cve_ids=["CVE-2024-8002"],
    )
    waiver = EvidenceException(
        exception_id="EX-INLINE",
        control_id="SSDF-PW.4",
        approver="appsec-team",
        approved_at=now - timedelta(days=1),
        expires_at=now + timedelta(days=30),
        justification="Risk accepted for the next 30 days while we patch.",
        reference="JIRA-9999",
    )
    bundle = _bundle([sbom], exceptions=[waiver])
    doc = build_openvex(bundle, now=now)
    statement = doc["statements"][0]
    assert statement["status"] == STATUS_NOT_AFFECTED
    assert "EX-INLINE" in statement["status_notes"]


def test_build_openvex_inline_unknown_state_falls_back_to_default() -> None:
    """An inline state we cannot map to OpenVEX must not poison the statement."""
    sbom = _sbom_evidence_with_inline_analyses(
        [{"cve_id": "CVE-2024-8003", "state": "no_such_state"}],
        cve_ids=["CVE-2024-8003"],
    )
    bundle = _bundle([sbom])
    doc = build_openvex(bundle, now=datetime(2026, 5, 18, tzinfo=UTC))
    statement = doc["statements"][0]
    # Fall back to under_investigation, exactly as if the analysis were absent.
    assert statement["status"] == STATUS_UNDER_INVESTIGATION
