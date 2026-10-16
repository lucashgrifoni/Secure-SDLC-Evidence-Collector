"""The CRA projection is pinned byte for byte.

Moving the ENISA SRP field taxonomy out of ``_cra_metadata`` into a data table
must not change one byte of what ``--profile cra-2026`` writes. The golden file
was captured from the code before that move. Only a deliberate change (a new
glossary version, a new key) may update it, and the diff then shows exactly
what moved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.application import profiles
from tests.unit.test_profiles_and_guac import _bundle, _evidence

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "cra_profile_golden.json"

_RELEASE = {"release_id": "2026.05.19", "commit_sha": "abcdef1234567890"}

CASES: dict[str, dict[str, Any] | None] = {
    "no_context": None,
    "vulnerability_full": {
        **_RELEASE,
        "notification_type": "vulnerability",
        "awareness_at": "2026-10-01T10:00:00-03:00",
        "corrective_measure_available_at": "2026-10-04T12:00:00Z",
        "euvd_ids": ["EUVD-2026-45012", "EUVD-2026-4893"],
        "srp_fields": {"1": "Vulnerability", "2": "A title", "v21": "General", "40": "Note"},
    },
    "vulnerability_bare": {**_RELEASE, "notification_type": "vulnerability"},
    "incident_full": {
        **_RELEASE,
        "notification_type": "incident",
        "awareness_at": "2026-12-01T08:00:00Z",
        "notification_72h_submitted_at": "2027-01-31T12:00:00Z",
        "srp_fields": {"i31": "Unknown", "i32": "Nature", "i38": "2026-11-30", "16": "Fix"},
    },
    "incident_bare": {**_RELEASE, "notification_type": "incident"},
    "awareness_before_obligation_start": {
        **_RELEASE,
        "notification_type": "vulnerability",
        "awareness_at": "2026-09-10T23:59:59Z",
    },
}


def render(case: str) -> dict[str, Any]:
    raw = CASES[case]
    context = profiles.CraReportingContext.model_validate(raw) if raw is not None else None
    bundle = profiles.apply_profile(
        _bundle([_evidence(in_kev=True)]), profiles.ReleaseProfile.CRA_2026, cra_context=context
    )
    cra: dict[str, Any] = bundle.evidence[0].metadata["cra"]
    return cra


@pytest.mark.parametrize("case", sorted(CASES))
def test_cra_projection_matches_the_golden_bytes(case: str) -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    expected = json.dumps(golden[case], sort_keys=True, separators=(",", ":"))
    actual = json.dumps(render(case), sort_keys=True, separators=(",", ":"))
    assert actual == expected


def test_the_golden_file_covers_every_case() -> None:
    assert sorted(json.loads(GOLDEN.read_text(encoding="utf-8"))) == sorted(CASES)
