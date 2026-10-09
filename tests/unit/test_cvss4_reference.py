"""Compare scoring to FIRST's pinned BSD-2 reference calculator."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import pytest

from evidence_collector.parsers import _cvss4
from evidence_collector.parsers.osv import _bucket_for_vulnerability, _extract_cvss_score

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cvss4_reference.json"
REFERENCE = json.loads(FIXTURE.read_text(encoding="utf-8"))
VALID = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
BASE = {
    "AV": "NALP",
    "AC": "LH",
    "AT": "NP",
    "PR": "NLH",
    "UI": "NPA",
    "VC": "HLN",
    "VI": "HLN",
    "VA": "HLN",
    "SC": "HLN",
    "SI": "HLN",
    "SA": "HLN",
}


def test_base_threat_and_environmental_scores_match_the_reference() -> None:
    for case in REFERENCE["cases"]:
        score = _extract_cvss_score({"type": "CVSS_V4", "score": case["vector"]})
        assert score == case["score"], case["vector"]


def test_all_base_vectors_have_the_reference_fingerprint() -> None:
    digest = hashlib.sha256()
    count = 0
    for values in itertools.product(*BASE.values()):
        vector = "CVSS:4.0/" + "/".join(
            f"{name}:{value}" for name, value in zip(BASE, values, strict=True)
        )
        score = _extract_cvss_score({"type": "CVSS_V4", "score": vector})
        assert score is not None, vector
        digest.update(f"{vector}|{score:.1f}\n".encode())
        count += 1
    assert count == REFERENCE["base_count"] == 104_976
    assert digest.hexdigest() == REFERENCE["base_sha256"]


@pytest.mark.parametrize("score", ["nan", "inf", "-inf", "-1", "10.1", "nonsense/9"])
def test_nonfinite_or_out_of_range_numeric_scores_are_not_evidence(score: str) -> None:
    assert _extract_cvss_score({"type": "CVSS_V4", "score": score}) is None


@pytest.mark.parametrize(
    "suffix",
    ["/AV:N", "/UNKNOWN:H", "/E:Y", "/SI:S", "/", "/IR:H/CR:H"],
)
def test_invalid_metric_values_duplicates_and_order_are_rejected(suffix: str) -> None:
    assert _extract_cvss_score({"type": "CVSS_V4", "score": VALID + suffix}) is None


# Each value is a substring of the metric's allowed letters, so a substring
# test would accept it and the later table lookup would raise KeyError.
MULTI_LETTER = [
    VALID.replace("AV:N", "AV:NA"),
    VALID.replace("AV:N", "AV:NALP"),
    VALID.replace("AC:L", "AC:LH"),
    VALID + "/E:AP",
    VALID + "/CR:XH",
    VALID + "/MSI:SH",
    VALID + "/S:NP",
    VALID + "/RE:LM",
    # All six impacts are N, so the 0.0 shortcut runs before any lookup.
    "CVSS:4.0/AV:NA/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
]


@pytest.mark.parametrize("vector", MULTI_LETTER)
def test_multi_letter_metric_values_are_rejected(vector: str) -> None:
    assert _extract_cvss_score({"type": "CVSS_V4", "score": vector}) is None


@pytest.mark.parametrize("vector", MULTI_LETTER)
def test_malformed_vector_falls_back_to_the_advisory_severity(vector: str) -> None:
    vuln = {
        "severity": [{"type": "CVSS_V4", "score": vector}],
        "database_specific": {"severity": "HIGH"},
    }
    assert _bucket_for_vulnerability(vuln) == "high"


def test_unexpected_lookup_failure_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_cvss4, "LOOKUP", {})
    assert _cvss4.score_cvss4(VALID) is None
