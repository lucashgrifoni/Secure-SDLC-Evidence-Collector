"""SARIF classification calibration suite.

`tests/unit/test_classification_edges.py` already covers the **happy
path** of the SARIF driver -> evidence type heuristic (every known
tool maps to its bucket, unknown drivers default to `sast_scan`).

This file is the **calibration** counterpart: it locks down the
documented false-positive / false-negative behaviour from
`docs/limitations.md §2` so any future change to
`evidence_collector.normalizers.engine._classify_sarif` either
preserves the documented contract or has to update the doc and
this test in the same diff.

Each test below cites the exact paragraph of `limitations.md` it
encodes. If you delete a paragraph there, delete the test here.
"""

from __future__ import annotations

import pytest

from evidence_collector.domain.enums import EvidenceType
from evidence_collector.normalizers.engine import _classify_sarif

# ---------------------------------------------------------------------------
# limitations.md §2 - "False-positive risk: a Trivy SARIF with a vuln run and
# a secret run in the same file is classified as `sca_scan`; the secret run
# is counted under SCA rather than under `secrets_scan`."
#
# We test the run-level classification: Trivy's *driver name* always lands
# under SCA, even when the operator runs `trivy fs --scanners secret`. The
# documented mitigation is to export the secret scan to a separate file
# (or use Gitleaks/TruffleHog), which then classifies as SECRETS_SCAN by
# driver name.
# ---------------------------------------------------------------------------


def test_trivy_driver_always_classifies_as_sca_even_for_secret_scans() -> None:
    """Locks the documented FP from limitations.md §2.

    A Trivy run whose ruleset is a secret scan is still labelled `sca_scan`
    because classification is by **driver name**, not by ruleset content.
    Operators must split secret scans into their own SARIF file (or use a
    dedicated tool) to get a `secrets_scan` label.
    """
    assert _classify_sarif("Trivy", None) is EvidenceType.SCA_SCAN
    assert _classify_sarif("trivy", None) is EvidenceType.SCA_SCAN
    assert _classify_sarif("Trivy Vulnerability Scanner", None) is EvidenceType.SCA_SCAN


def test_dedicated_secret_tool_recovers_secrets_scan_label() -> None:
    """The mitigation path for the FP above: use Gitleaks / TruffleHog,
    which classify by their own driver names regardless of what the file
    is alongside.
    """
    assert _classify_sarif("Gitleaks", None) is EvidenceType.SECRETS_SCAN
    assert _classify_sarif("TruffleHog", None) is EvidenceType.SECRETS_SCAN


# ---------------------------------------------------------------------------
# limitations.md §2 - "False-negative risk: an unknown driver defaults to
# `sast_scan`. If the driver was actually a DAST tool, the `sast_scan`
# control is credited while `dast_scan` remains missing."
#
# This is by design - SARIF cannot self-declare a tool category, so the
# fallback must pick one. SAST is the conservative pick because it does
# the *least* harm: an unknown DAST scanner mis-labelled as SAST still
# leaves DAST controls visibly missing in the bundle. The opposite
# (defaulting to DAST) would silently credit DAST coverage that does
# not exist.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dast_or_misc_driver",
    [
        "OWASP ZAP",  # ZAP also produces SARIF in some CI configs
        "Burp Suite",
        "Nuclei",
        "Wapiti",
        "Acunetix",
        "Invicti",
        "AppSpider",
    ],
)
def test_dast_tool_in_sarif_falls_back_to_sast_label(dast_or_misc_driver: str) -> None:
    """Locks the documented FN from limitations.md §2.

    DAST tools that emit SARIF land in the SAST bucket. The bundle's
    rationale field is what surfaces the actual tool name; the operator
    is responsible for additionally providing a `dast_scan` evidence
    (e.g. via `parsers/zap.py` or a `generic_attestation`).
    """
    assert _classify_sarif(dast_or_misc_driver, None) is EvidenceType.SAST_SCAN


def test_dast_tool_can_be_recovered_via_explicit_override() -> None:
    """Mitigation path for the FN above: callers that *know* the SARIF is
    DAST output pass `evidence_type_override=DAST_SCAN`. This is the same
    contract that `_classify_sarif` exposes today.
    """
    assert _classify_sarif("OWASP ZAP", EvidenceType.DAST_SCAN) is EvidenceType.DAST_SCAN


# ---------------------------------------------------------------------------
# Confusable substrings - guard against future regressions where a SAST tool
# matches the SCA token (or vice versa) by accident.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("driver", "expected"),
    [
        # "snyk" alone -> SCA. "snyk-code" / "snyk code" -> SAST. Tested in
        # _edges.py too; recapped here as a calibration anchor.
        ("Snyk", EvidenceType.SCA_SCAN),
        ("Snyk Open Source", EvidenceType.SCA_SCAN),
        ("Snyk Container", EvidenceType.SCA_SCAN),
        ("Snyk Code", EvidenceType.SAST_SCAN),
        ("snyk_code", EvidenceType.SAST_SCAN),
        # Bandit fork variants must keep landing in SAST.
        ("PyBandit", EvidenceType.SAST_SCAN),
        ("custom-bandit-wrapper", EvidenceType.SAST_SCAN),
        # Checkov is IaC but classifier treats it as SAST (limitation:
        # we don't have an IaC bucket in the catalog yet).
        ("Checkov", EvidenceType.SAST_SCAN),
    ],
)
def test_confusable_drivers_keep_their_documented_bucket(
    driver: str, expected: EvidenceType
) -> None:
    assert _classify_sarif(driver, None) is expected


# ---------------------------------------------------------------------------
# Empty / pathological driver names. limitations.md §2 paragraph "Mitigation"
# requires the bundle to still produce *some* label so the artifact is not
# silently dropped. SAST is the chosen fallback.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pathological",
    [
        "",
        "   ",
        "​",  # zero-width space
        "?",
        "unknown",
        "scanner",
        "tool",
    ],
)
def test_pathological_driver_falls_back_to_sast(pathological: str) -> None:
    assert _classify_sarif(pathological, None) is EvidenceType.SAST_SCAN
