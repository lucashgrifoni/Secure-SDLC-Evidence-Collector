"""OSV severity from CVSS vector strings.

The OSV schema carries CVSS as a vector in ``severity[*].score``, for example
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``. The parser only understood a
bare number, so every record rated by vector fell back to ``medium``: a 9.8
critical was counted as medium, and a release gate reading the counts saw a
smaller problem than the report described.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.parsers import parse_osv


def _record(tmp_path: Path, severity: list[dict[str, Any]], **extra: Any) -> Path:
    payload: dict[str, Any] = {
        "id": "GHSA-test-0001",
        "affected": [{"package": {"name": "demo", "ecosystem": "PyPI"}}],
        "severity": severity,
        **extra,
    }
    target = tmp_path / "osv.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _bucket(path: Path) -> str:
    counts = parse_osv(path).findings_count
    [bucket] = [name for name, count in counts.items() if count]
    return bucket


# Base scores published by NVD for these vectors.
@pytest.mark.parametrize(
    ("vector", "bucket"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),  # 9.8
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "critical"),  # 10.0
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "high"),  # 8.8
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "high"),  # 7.8
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "high"),  # 7.5
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "medium"),  # 6.1
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "medium"),  # 5.5
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "medium"),  # 5.3
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),  # 9.8
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "low"),  # 1.6
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "info"),  # 0.0
    ],
)
def test_a_cvss3_vector_is_scored(tmp_path: Path, vector: str, bucket: str) -> None:
    path = _record(tmp_path, [{"type": "CVSS_V3", "score": vector}])
    assert _bucket(path) == bucket


def test_the_highest_entry_wins_across_vectors_and_numbers(tmp_path: Path) -> None:
    path = _record(
        tmp_path,
        [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        ],
    )
    assert _bucket(path) == "critical"


def test_an_incomplete_vector_is_not_scored(tmp_path: Path) -> None:
    path = _record(tmp_path, [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N"}])
    assert _bucket(path) == "medium"


def test_a_v4_only_record_uses_the_advisory_severity(tmp_path: Path) -> None:
    """GitHub advisories carry a qualitative rating next to the vector."""
    path = _record(
        tmp_path,
        [
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            }
        ],
        database_specific={"severity": "CRITICAL"},
    )
    assert _bucket(path) == "critical"


def test_moderate_maps_to_medium(tmp_path: Path) -> None:
    path = _record(tmp_path, [], database_specific={"severity": "MODERATE"})
    assert _bucket(path) == "medium"


def test_a_v4_only_record_without_a_rating_still_falls_back_to_medium(tmp_path: Path) -> None:
    path = _record(
        tmp_path,
        [
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            }
        ],
    )
    assert _bucket(path) == "medium"


def test_changed_scope_uses_the_base_equation() -> None:
    """CVSS 3.1 keeps the 3.0 base equation for a changed scope.

    The specification's section 7.1 gives the base Impact for a changed scope
    as ``7.52 x (ISS - 0.029) - 3.25 x (ISS - 0.02)^15``. The ``0.9731`` and
    ``^13`` form belongs to section 7.3, the Environmental ModifiedImpact, and
    scores this vector 7.0 instead of its base 6.9.
    """
    from evidence_collector.parsers.osv import _cvss3_base_score

    assert _cvss3_base_score("CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H") == 6.9
