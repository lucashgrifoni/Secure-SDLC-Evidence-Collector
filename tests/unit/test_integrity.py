"""Unit tests for the structural integrity helpers.

These complement the bundle-level snapshot in
``tests/integration/test_bundle_snapshot.py`` by locking the *behavior*
of :func:`normalize_bundle` directly, so a regression in the helper
fails this granular test before it bubbles up to the snapshot gate.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from evidence_collector.application.integrity import normalize_bundle


def _sha(data: dict[str, Any]) -> str:
    return hashlib.sha256(normalize_bundle(data)).hexdigest()


def test_normalize_strips_volatile_top_level_fields() -> None:
    a = {"bundle_id": "x", "generated_at": "2026", "stable": 1}
    b = {"bundle_id": "y", "generated_at": "2027", "stable": 1}
    assert _sha(a) == _sha(b)


def test_normalize_strips_volatile_evidence_and_control_timestamps() -> None:
    a = {
        "evidence": [{"id": "e1", "collected_at": "2026"}],
        "control_evaluations": [{"id": "c1", "evaluated_at": "2026"}],
    }
    b = {
        "evidence": [{"id": "e1", "collected_at": "2099"}],
        "control_evaluations": [{"id": "c1", "evaluated_at": "2099"}],
    }
    assert _sha(a) == _sha(b)


def test_normalize_makes_artifact_path_cross_os_stable() -> None:
    """Windows ``\\`` and POSIX ``/`` artifact paths hash identically.

    This is the regression guard for the 2026-05-17 cross-OS snapshot
    drift: the snapshot test was failing on Windows because the helper
    treated ``raw.artifact_path`` literally, baking the host separator
    into the digest.
    """
    windows = {
        "evidence": [{"raw": {"artifact_path": "examples\\sample_release\\artifacts\\junit.xml"}}]
    }
    posix = {
        "evidence": [{"raw": {"artifact_path": "examples/sample_release/artifacts/junit.xml"}}]
    }
    assert _sha(windows) == _sha(posix)


def test_normalize_handles_raw_as_list_of_refs() -> None:
    """``raw`` may be a list in future schemas; the helper must still work."""
    windows_list = {
        "evidence": [
            {
                "raw": [
                    {"artifact_path": "a\\b\\c.json"},
                    {"artifact_path": "x\\y\\z.json"},
                ]
            }
        ]
    }
    posix_list = {
        "evidence": [
            {
                "raw": [
                    {"artifact_path": "a/b/c.json"},
                    {"artifact_path": "x/y/z.json"},
                ]
            }
        ]
    }
    assert _sha(windows_list) == _sha(posix_list)


def test_normalize_preserves_non_volatile_string_changes() -> None:
    """Changing a meaningful field must change the hash."""
    a = {"application": {"name": "payments-api"}}
    b = {"application": {"name": "shipping-api"}}
    assert _sha(a) != _sha(b)


def test_normalize_is_deterministic_across_calls() -> None:
    payload = json.loads(
        json.dumps(
            {
                "bundle_id": "x",
                "generated_at": "2026",
                "evidence": [
                    {"id": "e1", "collected_at": "2026", "raw": {"artifact_path": "a\\b"}}
                ],
                "control_evaluations": [{"id": "c1", "evaluated_at": "2026"}],
                "application": {"name": "payments-api"},
            }
        )
    )
    first = _sha(json.loads(json.dumps(payload)))
    second = _sha(json.loads(json.dumps(payload)))
    assert first == second
