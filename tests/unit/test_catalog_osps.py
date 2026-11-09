"""Tests for the bundled OpenSSF OSPS Baseline catalog."""

from __future__ import annotations

from evidence_collector.controls.catalog import (
    bundled_catalog_path,
    default_catalog,
    load_catalog,
)
from evidence_collector.controls.engine import evaluate_control
from evidence_collector.domain.enums import ControlEvaluationStatus, EvidenceType
from evidence_collector.domain.models import ControlDefinition, ReleaseContext
from evidence_collector.normalizers import normalize_pr_metadata


def test_osps_baseline_catalog_loads_and_is_unique() -> None:
    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    assert controls
    ids = [c.control_id for c in controls]
    assert len(ids) == len(set(ids))  # load_catalog also rejects duplicates


def test_osps_baseline_covers_the_attestable_criteria() -> None:
    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    ids = {c.control_id for c in controls}
    assert {
        "OSPS-QA-02.02",
        "OSPS-BR-06.01",
        "OSPS-VM-05.03",
        "OSPS-VM-06.02",
        "OSPS-QA-06.01",
        "OSPS-QA-07.01",
        "OSPS-QA-03.01",
    } <= ids


def test_osps_baseline_maps_controls_to_expected_evidence() -> None:
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    assert EvidenceType.SBOM in controls["OSPS-QA-02.02"].required_evidence_types
    assert EvidenceType.ARTIFACT_SIGNATURE in controls["OSPS-BR-06.01"].required_evidence_types
    assert EvidenceType.SCA_SCAN in controls["OSPS-VM-05.03"].required_evidence_types
    assert EvidenceType.SAST_SCAN in controls["OSPS-VM-06.02"].required_evidence_types
    assert EvidenceType.TEST_RESULT in controls["OSPS-QA-06.01"].required_evidence_types
    assert EvidenceType.CODE_REVIEW in controls["OSPS-QA-07.01"].required_evidence_types
    assert EvidenceType.WORKFLOW_RUN in controls["OSPS-QA-03.01"].required_evidence_types


def test_osps_baseline_catalog_pins_the_current_upstream_release() -> None:
    """v2026.08.28 is the release baseline.openssf.org labels current.

    The catalog cited v2025-02-25, three releases behind, in a hyphenated
    form upstream does not use. The pin names the tag and its commit so the
    exact source text can be fetched again.
    """
    text = bundled_catalog_path("catalog-osps-baseline.yaml").read_text(encoding="utf-8")
    assert "v2026.08.28" in text
    assert "a26a7963f6fd098c1e82829322ec9e1196a4f294" in text
    assert "v2025-02-25" not in text


def test_osps_qa_07_01_names_a_human_approval_and_its_limit() -> None:
    """v2026.08.28 requires a non-author *human* approval.

    Code-review evidence counts approvals by reviewer login and cannot tell a
    bot account from a person, so the description says what is left to review.
    """
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    description = controls["OSPS-QA-07.01"].description
    assert "non-author human approval" in description
    assert "bot" in description


_RELEASE = ReleaseContext(release_id="1.0.0", commit_sha="f" * 40)


def _bot_only_review() -> dict[str, object]:
    """A pull request whose single approval on the head commit is a bot's."""
    return {
        "number": 12,
        "html_url": "https://github.com/acme/app/pull/12",
        "reviewers_required": 1,
        "reviewers_approved": 1,
        "bot_approvals": 1,
        "last_approval_after_last_commit": True,
        "head_sha": "f" * 40,
    }


def _osps_human_review_control() -> ControlDefinition:
    controls = load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    return next(c for c in controls if c.control_id == "OSPS-QA-07.01")


def test_osps_qa_07_01_is_not_met_by_review_evidence_alone() -> None:
    """A bot approval is passing ``code_review`` evidence, and nothing in that
    evidence shows a person approved. The control therefore stays partial
    until a reviewer attests to a human approver; it used to be met."""
    review = normalize_pr_metadata(_bot_only_review(), _RELEASE)
    pr_record = review.model_copy(
        update={"evidence_id": "att-pr", "evidence_type": EvidenceType.PR_METADATA}
    )
    control = _osps_human_review_control()

    evaluation, gaps = evaluate_control(control, [review, pr_record])

    assert evaluation.evaluation_status == ControlEvaluationStatus.PARTIAL
    assert evaluation.missing_recommended_evidence_types == [EvidenceType.GENERIC_ATTESTATION]
    assert evaluation.missing_required_evidence_types == []
    assert [gap.evidence_type for gap in gaps] == [EvidenceType.GENERIC_ATTESTATION]


def test_osps_qa_07_01_is_met_once_a_reviewer_attests_to_a_human_approver() -> None:
    review = normalize_pr_metadata(_bot_only_review(), _RELEASE)
    pr_record = review.model_copy(
        update={"evidence_id": "att-pr", "evidence_type": EvidenceType.PR_METADATA}
    )
    attestation = review.model_copy(
        update={
            "evidence_id": "att-human-review",
            "evidence_type": EvidenceType.GENERIC_ATTESTATION,
            "manual": True,
        }
    )

    evaluation, gaps = evaluate_control(
        _osps_human_review_control(), [review, pr_record, attestation]
    )

    assert evaluation.evaluation_status == ControlEvaluationStatus.MET
    assert "att-human-review" in evaluation.evidence_refs
    assert gaps == []


def test_a_bot_approval_leaves_the_default_code_review_control_as_it_was() -> None:
    """Only the opt-in OSPS control asks for a human; the default catalog's
    verdict for the same evidence is the one 4.2.0 gave (GOVERNANCE: no
    default verdict changes in 4.x)."""
    with_bot = normalize_pr_metadata(_bot_only_review(), _RELEASE)
    payload = {k: v for k, v in _bot_only_review().items() if k != "bot_approvals"}
    without_bot = normalize_pr_metadata(payload, _RELEASE)
    control = next(c for c in default_catalog() if c.control_id == "ORG-CODE-REVIEW")

    assert with_bot.status == without_bot.status
    assert evaluate_control(control, [with_bot])[0].evaluation_status == (
        evaluate_control(control, [without_bot])[0].evaluation_status
    )


def test_osps_baseline_adds_attestable_controls_as_recommended_only() -> None:
    controls = {
        c.control_id: c for c in load_catalog(bundled_catalog_path("catalog-osps-baseline.yaml"))
    }
    threat_model = controls["OSPS-SA-03.02"]
    assert threat_model.required_evidence_types == []
    assert threat_model.recommended_evidence_types == [EvidenceType.THREAT_MODEL]
    version_id = controls["OSPS-BR-02.01"]
    assert version_id.required_evidence_types == []
    assert version_id.recommended_evidence_types == [EvidenceType.ARTIFACT_ATTESTATION]
    # VM-04.02 needs VEX documents as evidence and DO-05.01 an end-of-support
    # statement; neither is an evidence type the collector reads yet.
    assert "OSPS-VM-04.02" not in controls
    assert "OSPS-DO-05.01" not in controls
