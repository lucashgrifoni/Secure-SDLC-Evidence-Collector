"""Tests for the SLSA Verification Summary Attestation (VSA) parser + normalizer.

Covers the happy paths (PASSED / FAILED), the rejection of incomplete or
anonymous VSAs (missing required predicate fields), the rejection of non-VSA
predicate types, the normalizer's status mapping and subject-ref fallback, and
end-to-end detection through the local artifact collector.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_vsa
from evidence_collector.parsers import parse_vsa
from evidence_collector.parsers._common import ParseError

_VSA_PREDICATE = "https://slsa.dev/verification_summary/v1"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


def _vsa(result: str = "PASSED", **predicate_overrides: Any) -> dict[str, Any]:
    predicate: dict[str, Any] = {
        "verifier": {"id": "https://github.com/slsa-framework/slsa-verifier"},
        "timeVerified": "2026-06-17T12:00:00Z",
        "resourceUri": "pkg:pypi/demo@1.0.0",
        "policy": {"uri": "https://example.com/policy"},
        "verificationResult": result,
        "verifiedLevels": ["SLSA_BUILD_LEVEL_3"],
        "inputAttestations": [{"uri": "att1"}],
        "slsaVersion": "1.0",
    }
    predicate.update(predicate_overrides)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pkg:pypi/demo@1.0.0", "digest": {"sha256": "deadbeef"}}],
        "predicateType": _VSA_PREDICATE,
        "predicate": predicate,
    }


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "vsa.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_vsa_passed(tmp_path: Path) -> None:
    parsed = parse_vsa(_write(tmp_path, _vsa("PASSED")))
    assert parsed.verification_result == "PASSED"
    assert parsed.verifier_id == "https://github.com/slsa-framework/slsa-verifier"
    assert parsed.verified_levels == ["SLSA_BUILD_LEVEL_3"]
    assert parsed.slsa_version == "1.0"
    assert parsed.policy_uri == "https://example.com/policy"
    assert parsed.resource_uri == "pkg:pypi/demo@1.0.0"
    assert parsed.time_verified == "2026-06-17T12:00:00Z"
    assert parsed.subject_name == "pkg:pypi/demo@1.0.0"
    assert parsed.input_attestation_count == 1


def test_parse_vsa_lowercase_result_is_uppercased(tmp_path: Path) -> None:
    parsed = parse_vsa(_write(tmp_path, _vsa("passed")))
    assert parsed.verification_result == "PASSED"


def test_parse_vsa_filters_non_string_verified_levels(tmp_path: Path) -> None:
    parsed = parse_vsa(_write(tmp_path, _vsa(verifiedLevels=["SLSA_BUILD_LEVEL_3", 5, "FAILED"])))
    assert parsed.verified_levels == ["SLSA_BUILD_LEVEL_3", "FAILED"]


def test_parse_vsa_subject_not_a_list_yields_no_subject_name(tmp_path: Path) -> None:
    payload = _vsa()
    payload["subject"] = "nope"
    parsed = parse_vsa(_write(tmp_path, payload))
    assert parsed.subject_name is None


def test_parse_vsa_subject_name_skips_malformed_entries(tmp_path: Path) -> None:
    payload = _vsa()
    payload["subject"] = ["not-a-dict", {"name": ""}, {"name": "real-subject"}]
    parsed = parse_vsa(_write(tmp_path, payload))
    assert parsed.subject_name == "real-subject"


def test_parse_vsa_rejects_wrong_predicate_type(tmp_path: Path) -> None:
    payload = _vsa()
    payload["predicateType"] = "https://slsa.dev/provenance/v1"
    with pytest.raises(ParseError):
        parse_vsa(_write(tmp_path, payload))


def test_parse_vsa_rejects_missing_predicate(tmp_path: Path) -> None:
    payload = _vsa()
    del payload["predicate"]
    with pytest.raises(ParseError):
        parse_vsa(_write(tmp_path, payload))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("verifier"),
        lambda p: p.__setitem__("verifier", {}),
        lambda p: p.pop("verificationResult"),
        lambda p: p.pop("timeVerified"),
        lambda p: p.pop("resourceUri"),
        lambda p: p.pop("policy"),
        lambda p: p.pop("verifiedLevels"),
        lambda p: p.__setitem__("verifiedLevels", []),
    ],
)
def test_parse_vsa_rejects_incomplete_predicate(
    tmp_path: Path, mutate: Callable[[dict[str, Any]], Any]
) -> None:
    payload = _vsa()
    mutate(payload["predicate"])
    with pytest.raises(ParseError):
        parse_vsa(_write(tmp_path, payload))


def test_normalize_vsa_passed(tmp_path: Path) -> None:
    parsed = parse_vsa(_write(tmp_path, _vsa("PASSED")))
    ev = normalize_vsa(parsed, _release())
    assert ev.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    assert ev.status == EvidenceStatus.PASSED
    assert ev.subject_ref == "pkg:pypi/demo@1.0.0"
    assert ev.producer == "https://github.com/slsa-framework/slsa-verifier"
    assert ev.metadata["verified_levels"] == ["SLSA_BUILD_LEVEL_3"]
    assert ev.metadata["verification_result"] == "PASSED"
    assert ev.metadata["policy_uri"] == "https://example.com/policy"
    assert ev.metadata["slsa_version"] == "1.0"
    assert ev.metadata["input_attestation_count"] == 1
    assert ev.evidence_id.startswith("vsa-")


def test_normalize_vsa_failed(tmp_path: Path) -> None:
    parsed = parse_vsa(_write(tmp_path, _vsa("FAILED")))
    ev = normalize_vsa(parsed, _release())
    assert ev.status == EvidenceStatus.FAILED


def test_normalize_vsa_unknown_result_falls_back_to_resource_uri(tmp_path: Path) -> None:
    payload = _vsa("INDETERMINATE")
    payload["subject"] = []  # no subject -> subject_ref falls back to resourceUri
    parsed = parse_vsa(_write(tmp_path, payload))
    ev = normalize_vsa(parsed, _release())
    assert ev.status == EvidenceStatus.UNKNOWN
    assert ev.subject_ref == "pkg:pypi/demo@1.0.0"


def test_normalize_vsa_minimal_valid_omits_optional_metadata(tmp_path: Path) -> None:
    payload = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": _VSA_PREDICATE,
        "predicate": {
            "verifier": {"id": "vfr"},
            "timeVerified": "2026-06-18T00:00:00Z",
            "resourceUri": "pkg:demo",
            "policy": {"digest": {"sha256": "x"}},  # no uri
            "verificationResult": "PASSED",
            "verifiedLevels": ["SLSA_BUILD_LEVEL_2"],
        },
    }
    parsed = parse_vsa(_write(tmp_path, payload))
    assert parsed.policy_uri is None
    assert parsed.slsa_version is None
    assert parsed.input_attestation_count == 0
    ev = normalize_vsa(parsed, _release())
    assert ev.subject_ref == "pkg:demo"
    assert ev.producer == "vfr"
    assert "policy_uri" not in ev.metadata
    assert "slsa_version" not in ev.metadata
    assert "input_attestation_count" not in ev.metadata


def test_local_collector_ingests_vsa(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _vsa("PASSED"), name="release.vsa.json")
    collector = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts])
    report = collector.collect()
    vsa_evidence = [
        e for e in report.evidence if e.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    ]
    assert len(vsa_evidence) == 1
    assert vsa_evidence[0].status == EvidenceStatus.PASSED
    assert not report.errors
