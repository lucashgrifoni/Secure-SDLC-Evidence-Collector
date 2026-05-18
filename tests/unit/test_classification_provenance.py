"""Tests for the first-class ``classification`` field on SARIF evidence.

Covers the three reasons emitted by
``evidence_collector.normalizers.engine._classify_sarif_with_provenance``:

* ``driver_match`` — HIGH confidence, driver name matches a known set.
* ``manual_override`` — MEDIUM confidence, caller forced the evidence type.
* ``fallback_sast`` — LOW confidence, no token matched and the heuristic
  defaulted to ``sast_scan``.

The bundle-level integration is exercised separately by the existing
``test_classification_calibration.py`` suite, which now also benefits
from the explicit confidence signal once the bundle is serialized.
"""

from __future__ import annotations

from evidence_collector.domain.enums import ConfidenceLevel, EvidenceType
from evidence_collector.normalizers.engine import _classify_sarif_with_provenance


def test_known_sast_driver_yields_driver_match_high_confidence() -> None:
    evidence_type, classification = _classify_sarif_with_provenance("Semgrep", None)
    assert evidence_type is EvidenceType.SAST_SCAN
    assert classification.reason == "driver_match"
    assert classification.confidence is ConfidenceLevel.HIGH
    assert classification.driver_name == "Semgrep"


def test_known_secrets_driver_yields_driver_match_high_confidence() -> None:
    evidence_type, classification = _classify_sarif_with_provenance("Gitleaks", None)
    assert evidence_type is EvidenceType.SECRETS_SCAN
    assert classification.reason == "driver_match"
    assert classification.confidence is ConfidenceLevel.HIGH


def test_known_sca_driver_yields_driver_match_high_confidence() -> None:
    evidence_type, classification = _classify_sarif_with_provenance("Trivy", None)
    assert evidence_type is EvidenceType.SCA_SCAN
    assert classification.reason == "driver_match"
    assert classification.confidence is ConfidenceLevel.HIGH


def test_explicit_override_yields_manual_override_medium_confidence() -> None:
    evidence_type, classification = _classify_sarif_with_provenance(
        "OWASP ZAP", EvidenceType.DAST_SCAN
    )
    assert evidence_type is EvidenceType.DAST_SCAN
    assert classification.reason == "manual_override"
    assert classification.confidence is ConfidenceLevel.MEDIUM
    assert classification.driver_name == "OWASP ZAP"


def test_unknown_driver_falls_back_to_sast_with_low_confidence() -> None:
    evidence_type, classification = _classify_sarif_with_provenance(
        "Acme Proprietary Scanner", None
    )
    assert evidence_type is EvidenceType.SAST_SCAN
    assert classification.reason == "fallback_sast"
    assert classification.confidence is ConfidenceLevel.LOW
    assert classification.driver_name == "Acme Proprietary Scanner"


def test_legacy_classify_sarif_returns_only_evidence_type() -> None:
    """The single-return helper kept for backward compatibility must remain a
    pure projection of the provenance-aware version."""
    from evidence_collector.normalizers.engine import _classify_sarif

    assert _classify_sarif("Semgrep", None) is EvidenceType.SAST_SCAN
    assert _classify_sarif("Trivy", None) is EvidenceType.SCA_SCAN
    assert _classify_sarif("Gitleaks", None) is EvidenceType.SECRETS_SCAN
    assert _classify_sarif("Acme Proprietary Scanner", None) is EvidenceType.SAST_SCAN
    assert _classify_sarif("OWASP ZAP", EvidenceType.DAST_SCAN) is EvidenceType.DAST_SCAN
