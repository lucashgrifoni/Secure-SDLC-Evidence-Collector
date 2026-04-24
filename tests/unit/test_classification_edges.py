"""Edge-case tests for SARIF → evidence_type classification.

Covers the classification heuristic that maps a SARIF driver name to one of
`sast_scan` / `sca_scan` / `secrets_scan`. These tests are the false-positive
guardrail documented in `docs/limitations.md §2`.
"""

from __future__ import annotations

import pytest

from evidence_collector.domain.enums import EvidenceType
from evidence_collector.normalizers.engine import _classify_sarif


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("Semgrep OSS", EvidenceType.SAST_SCAN),
        ("semgrep", EvidenceType.SAST_SCAN),
        ("CodeQL", EvidenceType.SAST_SCAN),
        ("SonarQube", EvidenceType.SAST_SCAN),
        ("Snyk Code", EvidenceType.SAST_SCAN),
        ("Bandit", EvidenceType.SAST_SCAN),
        ("brakeman", EvidenceType.SAST_SCAN),
        ("Checkov", EvidenceType.SAST_SCAN),
        ("ESLint", EvidenceType.SAST_SCAN),
    ],
)
def test_known_sast_drivers(tool_name: str, expected: EvidenceType) -> None:
    assert _classify_sarif(tool_name, None) is expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("Trivy", EvidenceType.SCA_SCAN),
        ("trivy", EvidenceType.SCA_SCAN),
        ("Grype", EvidenceType.SCA_SCAN),
        ("Snyk", EvidenceType.SCA_SCAN),
        ("dependency-check", EvidenceType.SCA_SCAN),
        ("OWASP-Dependency-Check", EvidenceType.SCA_SCAN),
        ("osv-scanner", EvidenceType.SCA_SCAN),
        ("pip-audit", EvidenceType.SCA_SCAN),
        ("pip_audit", EvidenceType.SCA_SCAN),
        ("Safety", EvidenceType.SCA_SCAN),
        ("npm-audit", EvidenceType.SCA_SCAN),
        ("yarn-audit", EvidenceType.SCA_SCAN),
        ("retire.js", EvidenceType.SCA_SCAN),
        ("retire", EvidenceType.SCA_SCAN),
    ],
)
def test_known_sca_drivers(tool_name: str, expected: EvidenceType) -> None:
    assert _classify_sarif(tool_name, None) is expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("Gitleaks", EvidenceType.SECRETS_SCAN),
        ("gitleaks", EvidenceType.SECRETS_SCAN),
        ("TruffleHog", EvidenceType.SECRETS_SCAN),
        ("trufflehog", EvidenceType.SECRETS_SCAN),
        ("detect-secrets", EvidenceType.SECRETS_SCAN),
        ("NoseyParker", EvidenceType.SECRETS_SCAN),
        ("noseyparker", EvidenceType.SECRETS_SCAN),
    ],
)
def test_known_secrets_drivers(tool_name: str, expected: EvidenceType) -> None:
    assert _classify_sarif(tool_name, None) is expected


def test_unknown_driver_defaults_to_sast() -> None:
    # SAST is the conservative default when we cannot recognise the driver.
    assert _classify_sarif("acme-proprietary-scanner", None) is EvidenceType.SAST_SCAN


def test_empty_driver_defaults_to_sast() -> None:
    assert _classify_sarif("", None) is EvidenceType.SAST_SCAN


def test_override_wins_over_driver_name() -> None:
    # A caller that knows better (e.g., DAST tool producing SARIF) can override.
    assert _classify_sarif("Gitleaks", EvidenceType.DAST_SCAN) is EvidenceType.DAST_SCAN


def test_classification_prefers_sast_when_driver_contains_both_tokens() -> None:
    # "Snyk Code" contains both "snyk" (SCA) and "snyk-code" (SAST). The
    # SAST token is matched first which is the desired behaviour: more
    # specific tool → more specific label.
    assert _classify_sarif("Snyk Code", None) is EvidenceType.SAST_SCAN


def test_driver_token_is_substring_match() -> None:
    # `_SAST_TOOLS` contains "bandit"; the full driver string "PyBandit
    # (custom fork)" must still classify as SAST.
    assert _classify_sarif("PyBandit (custom fork)", None) is EvidenceType.SAST_SCAN
