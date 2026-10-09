"""Unit tests for the OpenVEX exporter.

The exporter is pure: given a bundle and an optional fixed clock, it
returns a deterministic ``dict``. Tests assert structure and the three
status-decision branches (under_investigation → affected → not_affected).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

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
    EvidenceException,
    EvidenceSource,
    ExceptionScope,
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
    merge_consumed_vex,
)
from evidence_collector.parsers.vex import VexStatement


def _evidence(
    cve_ids: list[str],
    *,
    evidence_id: str = "sca-1",
    top_risk: list[TopRiskCve] | None = None,
    status: EvidenceStatus = EvidenceStatus.GENERATED,
    evidence_type: EvidenceType = EvidenceType.SCA_SCAN,
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
        evidence_type=evidence_type,
        source=EvidenceSource(name="trivy", kind="sarif"),
        producer="trivy",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567890",
        status=status,
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


def _evaluation(
    control_id: str,
    status: ControlEvaluationStatus,
    *,
    exception_refs: list[str] | None = None,
    missing_required: list[EvidenceType] | None = None,
    evidence_refs: list[str] | None = None,
) -> ControlEvaluation:
    """A control evaluation as the engine records it in the bundle."""
    return ControlEvaluation(
        control_id=control_id,
        framework=ControlFramework.NIST_SSDF,
        control_name=f"Control {control_id}",
        evaluation_status=status,
        criticality=ControlCriticality.HIGH,
        evidence_refs=evidence_refs or [],
        missing_required_evidence_types=missing_required or [],
        rationale=f"Control {control_id} evaluated.",
        exception_refs=exception_refs or [],
    )


def _sca_waived(exception_id: str) -> ControlEvaluation:
    """SSDF-PW.4 waived because its required SCA evidence did not satisfy it."""
    return _evaluation(
        "SSDF-PW.4",
        ControlEvaluationStatus.WAIVED,
        exception_refs=[exception_id],
        missing_required=[EvidenceType.SCA_SCAN],
    )


def _rollback_waived(exception_id: str) -> ControlEvaluation:
    return _evaluation(
        "ORG-REL-ROLLBACK",
        ControlEvaluationStatus.WAIVED,
        exception_refs=[exception_id],
        missing_required=[EvidenceType.ROLLBACK_PLAN],
    )


def _waiver(
    now: datetime,
    *,
    exception_id: str = "EX-001",
    control_id: str = "SSDF-PW.4",
    approved_at: datetime | None = None,
    expires_at: datetime | None = None,
    release_id: str | None = None,
) -> EvidenceException:
    return EvidenceException(
        exception_id=exception_id,
        control_id=control_id,
        approver="security-team",
        approved_at=approved_at or now - timedelta(days=1),
        expires_at=expires_at or now + timedelta(days=30),
        justification="Library is loaded but the affected function is never called.",
        reference="JIRA-1234",
        scope=ExceptionScope(release_id=release_id),
    )


def _bundle(
    evidence: list[NormalizedEvidence],
    exceptions: list[EvidenceException] | None = None,
    evaluations: list[ControlEvaluation] | None = None,
    generated_at: datetime | None = None,
) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-vex-test",
        generated_at=generated_at or datetime(2026, 5, 18, tzinfo=UTC),
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.18", commit_sha="abcdef1234567890"),
        evidence=evidence,
        control_evaluations=evaluations or [],
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
    # The SCA scan failed on the CVE, so SSDF-PW.4 lacked satisfying SCA
    # evidence and the engine recorded it as waived by EX-001.
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.FAILED)],
        exceptions=[waiver],
        evaluations=[_sca_waived("EX-001")],
    )

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
    # A failed SCA scan reports the same CVE, and SSDF-PW.4 is waived for it.
    sca = _evidence(["CVE-2024-8002"], status=EvidenceStatus.FAILED)
    bundle = _bundle([sbom, sca], exceptions=[waiver], evaluations=[_sca_waived("EX-INLINE")])
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


# --- Waiver scope -----------------------------------------------------------

_NOW = datetime(2026, 5, 18, tzinfo=UTC)

_KEV_TOP = [
    TopRiskCve(
        cve_id="CVE-2024-2222",
        epss_score=0.95,
        epss_percentile=0.99,
        in_kev=True,
        known_ransomware=True,
    )
]


def _status_of(doc: dict[str, Any], cve_id: str) -> str:
    return str(next(s for s in doc["statements"] if s["vulnerability"]["name"] == cve_id)["status"])


def test_unrelated_waiver_does_not_mark_cves_not_affected() -> None:
    """A rollback waiver says nothing about a dependency CVE."""
    bundle = _bundle(
        [_evidence(["CVE-2024-12345"], status=EvidenceStatus.FAILED)],
        exceptions=[_waiver(_NOW, exception_id="EX-RB", control_id="ORG-REL-ROLLBACK")],
        evaluations=[_rollback_waived("EX-RB")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-12345") == STATUS_UNDER_INVESTIGATION


def test_waiver_the_engine_never_applied_does_not_apply() -> None:
    """A valid exception that waived no control waives no CVE."""
    bundle = _bundle([_evidence(["CVE-2024-3333"])], exceptions=[_waiver(_NOW)])
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_UNDER_INVESTIGATION


def test_unused_waiver_on_met_sca_control_does_not_apply() -> None:
    """The engine lists in-force waivers even on a met control; nothing was waived."""
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.PASSED)],
        exceptions=[_waiver(_NOW)],
        evaluations=[
            _evaluation(
                "SSDF-PW.4",
                ControlEvaluationStatus.MET,
                exception_refs=["EX-001"],
                evidence_refs=["sca-1"],
            )
        ],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_UNDER_INVESTIGATION


def test_waiver_only_covers_the_evidence_type_it_compensates_for() -> None:
    """A control waived for a missing SBOM does not waive CVEs from a passing SCA scan."""
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.PASSED)],
        exceptions=[_waiver(_NOW)],
        evaluations=[
            _evaluation(
                "SSDF-PW.4",
                ControlEvaluationStatus.WAIVED,
                exception_refs=["EX-001"],
                missing_required=[EvidenceType.SBOM],
                evidence_refs=["sca-1"],
            )
        ],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_UNDER_INVESTIGATION


def test_waiver_recorded_for_another_control_does_not_apply() -> None:
    """An exception id listed on a control it does not name is not a waiver of that control."""
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.FAILED)],
        exceptions=[_waiver(_NOW, exception_id="EX-RB", control_id="ORG-REL-ROLLBACK")],
        evaluations=[_sca_waived("EX-RB")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_UNDER_INVESTIGATION


@pytest.mark.parametrize(
    "waiver",
    [
        pytest.param(
            _waiver(
                _NOW, approved_at=_NOW - timedelta(days=9), expires_at=_NOW - timedelta(days=1)
            ),
            id="expired",
        ),
        pytest.param(
            _waiver(
                _NOW, approved_at=_NOW + timedelta(days=1), expires_at=_NOW + timedelta(days=9)
            ),
            id="not-yet-approved",
        ),
        pytest.param(_waiver(_NOW, release_id="some-other-release"), id="out-of-scope"),
    ],
)
def test_waiver_not_in_force_does_not_apply_even_if_recorded(waiver: EvidenceException) -> None:
    """The recorded evaluation alone is not enough: the waiver must be in force."""
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.FAILED)],
        exceptions=[waiver],
        evaluations=[_sca_waived("EX-001")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_UNDER_INVESTIGATION


def test_applied_sca_waiver_marks_only_the_cves_its_evidence_reports() -> None:
    bundle = _bundle(
        [
            _evidence(["CVE-2024-3333"], evidence_id="sca-1", status=EvidenceStatus.FAILED),
            _evidence(
                ["CVE-2024-4444"],
                evidence_id="sast-1",
                status=EvidenceStatus.FAILED,
                evidence_type=EvidenceType.SAST_SCAN,
            ),
        ],
        exceptions=[_waiver(_NOW)],
        evaluations=[_sca_waived("EX-001")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-3333") == STATUS_NOT_AFFECTED
    assert _status_of(doc, "CVE-2024-4444") == STATUS_UNDER_INVESTIGATION


def test_kev_cve_with_unrelated_waiver_stays_affected() -> None:
    bundle = _bundle(
        [_evidence(["CVE-2024-2222"], top_risk=_KEV_TOP, status=EvidenceStatus.FAILED)],
        exceptions=[_waiver(_NOW, exception_id="EX-RB", control_id="ORG-REL-ROLLBACK")],
        evaluations=[_rollback_waived("EX-RB")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-2222") == STATUS_AFFECTED


def test_kev_cve_with_applied_sca_waiver_is_not_affected() -> None:
    """An applied waiver keeps its existing precedence over the KEV default."""
    bundle = _bundle(
        [_evidence(["CVE-2024-2222"], top_risk=_KEV_TOP, status=EvidenceStatus.FAILED)],
        exceptions=[_waiver(_NOW)],
        evaluations=[_sca_waived("EX-001")],
    )
    doc = build_openvex(bundle, now=_NOW)
    assert _status_of(doc, "CVE-2024-2222") == STATUS_NOT_AFFECTED


# --- Determinism ------------------------------------------------------------


def test_two_runs_on_the_same_bundle_are_byte_identical() -> None:
    generated = datetime(2026, 5, 18, 9, 30, tzinfo=UTC)
    bundle = _bundle([_evidence(["CVE-2024-4444"])], generated_at=generated)
    first = json.dumps(build_openvex(bundle), sort_keys=True)
    second = json.dumps(build_openvex(bundle), sort_keys=True)
    assert first == second
    assert json.loads(first)["timestamp"] == generated.isoformat()


def test_default_clock_drives_waiver_validity() -> None:
    """Validity is judged at bundle generation time, not at export time."""
    generated = datetime(2020, 1, 10, tzinfo=UTC)
    waiver = _waiver(
        generated,
        approved_at=datetime(2020, 1, 1, tzinfo=UTC),
        expires_at=datetime(2020, 2, 1, tzinfo=UTC),
    )
    bundle = _bundle(
        [_evidence(["CVE-2024-3333"], status=EvidenceStatus.FAILED)],
        exceptions=[waiver],
        evaluations=[_sca_waived("EX-001")],
        generated_at=generated,
    )
    assert _status_of(build_openvex(bundle), "CVE-2024-3333") == STATUS_NOT_AFFECTED


def test_different_statements_produce_different_ids() -> None:
    base = _bundle([_evidence(["CVE-2024-4444"])])
    other = _bundle([_evidence(["CVE-2024-5555"])])
    assert build_openvex(base, now=_NOW)["@id"] != build_openvex(other, now=_NOW)["@id"]


def test_merge_recomputes_the_document_id() -> None:
    bundle = _bundle([_evidence(["CVE-2024-4444"])])
    doc = build_openvex(bundle, now=_NOW)
    original_id = doc["@id"]
    consumed = [VexStatement(cve_id="CVE-2024-4444", status="not_affected")]
    merged = merge_consumed_vex(doc, bundle, consumed)
    assert merged["@id"] != original_id
