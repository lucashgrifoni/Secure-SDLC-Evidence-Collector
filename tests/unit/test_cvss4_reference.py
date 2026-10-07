"""Compare scoring to FIRST's pinned BSD-2 reference calculator."""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import pytest

from evidence_collector.parsers.osv import _extract_cvss_score

REFERENCE = json.loads(Path("tests/fixtures/cvss4_reference.json").read_text(encoding="utf-8"))
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
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert _extract_cvss_score({"type": "CVSS_V4", "score": vector + suffix}) is None
