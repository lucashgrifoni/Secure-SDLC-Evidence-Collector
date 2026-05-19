"""§3.2 — Unit tests for the optional Reachability field."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.domain.enums import (
    ConfidenceLevel,
    EvidenceStatus,
    EvidenceType,
    SubjectType,
)
from evidence_collector.domain.models import (
    EvidenceSource,
    NormalizedEvidence,
    Reachability,
)


def _evidence(reachability: Reachability | None) -> NormalizedEvidence:
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
        reachability=reachability,
    )


def test_reachability_status_must_be_in_canonical_set() -> None:
    with pytest.raises(ValidationError):
        Reachability(status="exploitable", source="codeql")


def test_reachability_method_must_be_in_canonical_set() -> None:
    with pytest.raises(ValidationError):
        Reachability(status="reachable", source="codeql", method="guessing")


def test_reachability_status_is_case_normalised() -> None:
    reach = Reachability(status=" REACHABLE ", source="codeql", method="data_flow")
    assert reach.status == "reachable"
    assert reach.method == "data_flow"


def test_default_method_is_manual_review() -> None:
    reach = Reachability(status="unknown", source="manual")
    assert reach.method == "manual_review"


def test_evidence_without_reachability_hashes_like_pre_section_3_2() -> None:
    """Byte-stability invariant: an evidence without ``reachability`` must
    produce the same structural hash as an old bundle that did not have
    the field at all. The normaliser strips ``reachability: null`` so
    pre-§3.2 bundles do not drift on upgrade.
    """
    evidence_dict = _evidence(None).model_dump(mode="json")
    assert "reachability" in evidence_dict
    assert evidence_dict["reachability"] is None

    # Simulate a full bundle JSON: just feed the evidence list through
    # normalize_bundle by wrapping it in a minimal dict. Annotated as
    # ``dict[str, object]`` so dict invariance does not trip mypy.
    payload: dict[str, object] = {"evidence": [dict(evidence_dict)]}
    normalised = normalize_bundle(payload)
    assert b'"reachability"' not in normalised


def test_reachability_present_survives_normalisation() -> None:
    reach = Reachability(status="not_reachable", source="codeql", method="data_flow")
    evidence_dict = _evidence(reach).model_dump(mode="json")
    payload: dict[str, object] = {"evidence": [dict(evidence_dict)]}
    normalised = normalize_bundle(payload)
    assert b'"not_reachable"' in normalised
