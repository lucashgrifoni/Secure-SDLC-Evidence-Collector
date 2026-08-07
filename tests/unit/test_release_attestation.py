"""Tests for the in-toto release-attestation parser + normalizer.

Covers both predicate versions (``release/v0.1`` with ``releaseId`` and
``release/v0.2`` with ``packageId``), the rejection of an attestation missing
the spec-required ``purl``, extraction of the released assets from the
Statement ``subject`` array, every envelope shape the attestation travels in
(raw Statement, DSSE, Sigstore bundle, JSONL), the normalizer's metadata, and
end-to-end detection through the local artifact collector — including a JSONL
that carries a build provenance alongside the release attestation.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceStatus, EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_release_attestation
from evidence_collector.parsers import parse_release_attestation, parse_release_attestations
from evidence_collector.parsers._common import ParseError

_RELEASE_V01 = "https://in-toto.io/attestation/release/v0.1"
_RELEASE_V02 = "https://in-toto.io/attestation/release/v0.2"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2.1.0", commit_sha="abcdef1234567890", branch="main")


def _subjects() -> list[dict[str, Any]]:
    """The released assets, as the spec carries them: Statement subjects."""
    return [
        {"name": "urllib3-2.1.0.tar.gz", "digest": {"sha256": "df7aa8af"}},
        {"name": "urllib3-2.1.0-py3-none-any.whl", "digest": {"sha256": "55901e91"}},
    ]


def _statement(
    predicate_type: str = _RELEASE_V02,
    **predicate_overrides: Any,
) -> dict[str, Any]:
    predicate: dict[str, Any] = {"purl": "pkg:pypi/urllib3@2.1.0", "packageId": "urllib3"}
    predicate.update(predicate_overrides)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": _subjects(),
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def _write(tmp_path: Path, payload: Any, name: str = "release.json") -> Path:
    target = tmp_path / name
    text = payload if isinstance(payload, str) else json.dumps(payload)
    target.write_text(text, encoding="utf-8")
    return target


def _dsse(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "signatures": [{"sig": "AAAA"}],
    }


def _bundle(statement: dict[str, Any]) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "dsseEnvelope": _dsse(statement),
        "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}},
    }


def _provenance_statement() -> dict[str, Any]:
    """A SLSA build provenance — the other predicate a `gh attestation
    download` JSONL commonly carries."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "app.tar.gz", "digest": {"sha256": "cafe"}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://example.com/build"},
            "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
        },
    }


# ---------------------------------------------------------------------------
# Parsing — both predicate versions
# ---------------------------------------------------------------------------


def test_parse_release_v02_packageid(tmp_path: Path) -> None:
    parsed = parse_release_attestation(_write(tmp_path, _statement()))
    assert parsed.predicate_type == _RELEASE_V02
    assert parsed.purl == "pkg:pypi/urllib3@2.1.0"
    assert parsed.package_id == "urllib3"
    assert parsed.envelope == "statement"


def test_parse_release_v01_releaseid_is_read_as_package_id(tmp_path: Path) -> None:
    # in-toto v1.2.0 renamed releaseId -> packageId. Both versions coexist in
    # the wild, so a v0.1 attestation must still surface its identifier.
    payload = _statement(_RELEASE_V01)
    del payload["predicate"]["packageId"]
    payload["predicate"]["releaseId"] = "urllib3"
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert parsed.predicate_type == _RELEASE_V01
    assert parsed.package_id == "urllib3"


def test_parse_release_package_id_is_optional(tmp_path: Path) -> None:
    payload = _statement()
    del payload["predicate"]["packageId"]
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert parsed.package_id is None
    assert parsed.purl == "pkg:pypi/urllib3@2.1.0"


def test_parse_release_prefers_package_id_over_release_id(tmp_path: Path) -> None:
    payload = _statement()
    payload["predicate"]["releaseId"] = "legacy"
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert parsed.package_id == "urllib3"


# ---------------------------------------------------------------------------
# Assets come from the Statement subject array
# ---------------------------------------------------------------------------


def test_parse_release_extracts_assets_with_digests(tmp_path: Path) -> None:
    parsed = parse_release_attestation(_write(tmp_path, _statement()))
    assert [a.name for a in parsed.assets] == [
        "urllib3-2.1.0.tar.gz",
        "urllib3-2.1.0-py3-none-any.whl",
    ]
    assert parsed.assets[0].digests == {"sha256": "df7aa8af"}
    assert parsed.subject_name == "urllib3-2.1.0.tar.gz"


def test_parse_release_skips_malformed_subject_entries(tmp_path: Path) -> None:
    payload = _statement()
    payload["subject"] = [
        "not-a-dict",
        {"name": ""},
        {"digest": {"sha256": "x"}},
        {"name": "real.whl", "digest": {"sha256": "abc", "sha512": 7}},
    ]
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert [a.name for a in parsed.assets] == ["real.whl"]
    # Non-string digest values are dropped rather than carried into evidence.
    assert parsed.assets[0].digests == {"sha256": "abc"}


def test_parse_release_tolerates_subject_not_a_list(tmp_path: Path) -> None:
    payload = _statement()
    payload["subject"] = "nope"
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert parsed.assets == []
    assert parsed.subject_name is None


def test_parse_release_asset_without_digest_is_kept(tmp_path: Path) -> None:
    payload = _statement()
    payload["subject"] = [{"name": "notes.txt"}]
    parsed = parse_release_attestation(_write(tmp_path, payload))
    assert [a.name for a in parsed.assets] == ["notes.txt"]
    assert parsed.assets[0].digests == {}


# ---------------------------------------------------------------------------
# Rejection — purl is the only spec-required predicate field
# ---------------------------------------------------------------------------


def test_parse_release_rejects_missing_purl(tmp_path: Path) -> None:
    payload = _statement()
    del payload["predicate"]["purl"]
    with pytest.raises(ParseError, match="purl"):
        parse_release_attestation(_write(tmp_path, payload))


def test_parse_release_rejects_empty_purl(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="purl"):
        parse_release_attestation(_write(tmp_path, _statement(purl="")))


def test_parse_release_rejects_non_string_purl(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="purl"):
        parse_release_attestation(_write(tmp_path, _statement(purl=42)))


def test_parse_release_rejects_missing_predicate(tmp_path: Path) -> None:
    payload = _statement()
    del payload["predicate"]
    with pytest.raises(ParseError):
        parse_release_attestation(_write(tmp_path, payload))


def test_parse_release_rejects_wrong_predicate_type(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_release_attestation(_write(tmp_path, _provenance_statement()))


def test_parse_release_rejects_unversioned_release_predicate(tmp_path: Path) -> None:
    # Only the two vetted versions are accepted; a future /v0.3 must fail
    # loudly rather than be parsed under v0.2 assumptions.
    with pytest.raises(ParseError):
        parse_release_attestation(
            _write(tmp_path, _statement("https://in-toto.io/attestation/release/v0.3"))
        )


def test_parse_release_rejects_non_json(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_release_attestation(_write(tmp_path, "not json at all", name="junk.json"))


# ---------------------------------------------------------------------------
# Envelopes
# ---------------------------------------------------------------------------


def test_parse_release_from_dsse_envelope(tmp_path: Path) -> None:
    parsed = parse_release_attestation(_write(tmp_path, _dsse(_statement())))
    assert parsed.purl == "pkg:pypi/urllib3@2.1.0"
    assert parsed.envelope == "dsse"


def test_parse_release_from_sigstore_bundle(tmp_path: Path) -> None:
    parsed = parse_release_attestation(_write(tmp_path, _bundle(_statement())))
    assert parsed.purl == "pkg:pypi/urllib3@2.1.0"
    assert parsed.envelope == "sigstore-bundle"


def test_parse_release_from_jsonl_alongside_provenance(tmp_path: Path) -> None:
    # `gh attestation download` writes one bundle per line and can hold several
    # predicates. The release attestation must be found even when a build
    # provenance appears first.
    lines = "\n".join(
        json.dumps(record) for record in (_bundle(_provenance_statement()), _bundle(_statement()))
    )
    parsed = parse_release_attestation(_write(tmp_path, lines, name="attestations.jsonl"))
    assert parsed.purl == "pkg:pypi/urllib3@2.1.0"
    assert parsed.envelope == "sigstore-bundle"


def test_parse_release_jsonl_without_release_predicate_is_rejected(tmp_path: Path) -> None:
    lines = json.dumps(_bundle(_provenance_statement()))
    with pytest.raises(ParseError):
        parse_release_attestation(_write(tmp_path, lines, name="attestations.jsonl"))


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


def test_normalize_release_attestation(tmp_path: Path) -> None:
    parsed = parse_release_attestation(_write(tmp_path, _statement()))
    ev = normalize_release_attestation(parsed, _release())
    assert ev.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    # A release attestation asserts existence and binding, not a verdict.
    assert ev.status == EvidenceStatus.GENERATED
    assert ev.source.kind == "release-attestation"
    assert ev.metadata["purl"] == "pkg:pypi/urllib3@2.1.0"
    assert ev.metadata["package_id"] == "urllib3"
    assert ev.metadata["predicate_type"] == _RELEASE_V02
    assert ev.metadata["envelope"] == "statement"
    assert ev.metadata["asset_count"] == 2
    assert ev.metadata["assets"] == [
        {"name": "urllib3-2.1.0.tar.gz", "digests": {"sha256": "df7aa8af"}},
        {"name": "urllib3-2.1.0-py3-none-any.whl", "digests": {"sha256": "55901e91"}},
    ]
    assert ev.summary is not None and "urllib3" in ev.summary


def test_normalize_release_omits_absent_package_id(tmp_path: Path) -> None:
    payload = _statement()
    del payload["predicate"]["packageId"]
    parsed = parse_release_attestation(_write(tmp_path, payload))
    ev = normalize_release_attestation(parsed, _release())
    assert "package_id" not in ev.metadata


def test_normalize_release_subject_ref_falls_back_to_purl(tmp_path: Path) -> None:
    payload = _statement()
    payload["subject"] = []
    parsed = parse_release_attestation(_write(tmp_path, payload))
    ev = normalize_release_attestation(parsed, _release())
    assert ev.subject_ref == "pkg:pypi/urllib3@2.1.0"
    assert ev.metadata["asset_count"] == 0


def test_normalize_release_evidence_id_is_deterministic(tmp_path: Path) -> None:
    first = parse_release_attestation(_write(tmp_path, _statement(), name="a.json"))
    second = parse_release_attestation(_write(tmp_path, _statement(), name="b.json"))
    assert (
        normalize_release_attestation(first, _release()).evidence_id
        == normalize_release_attestation(second, _release()).evidence_id
    )


# ---------------------------------------------------------------------------
# End-to-end detection through the local collector
# ---------------------------------------------------------------------------


def test_collector_ingests_release_attestation(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _statement(), name="release-attestation.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    evidence = [e for e in report.evidence if e.evidence_type == EvidenceType.ARTIFACT_ATTESTATION]
    assert len(evidence) == 1
    assert evidence[0].source.kind == "release-attestation"
    assert evidence[0].status == EvidenceStatus.GENERATED
    assert not report.errors


def test_collector_ingests_both_predicates_from_one_jsonl(tmp_path: Path) -> None:
    # A `gh attestation download` JSONL can carry a build provenance and a
    # release attestation together. Neither may be dropped.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    lines = "\n".join(
        json.dumps(record) for record in (_bundle(_provenance_statement()), _bundle(_statement()))
    )
    _write(artifacts, lines, name="attestations.jsonl")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    kinds = sorted(e.source.kind for e in report.evidence)
    assert kinds == ["release-attestation", "slsa-provenance"]
    assert not report.errors


def test_collector_still_ingests_provenance(tmp_path: Path) -> None:
    # The new detector must not shadow the build-provenance route.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _provenance_statement(), name="provenance.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    evidence = [e for e in report.evidence if e.evidence_type == EvidenceType.ARTIFACT_ATTESTATION]
    assert len(evidence) == 1
    assert evidence[0].source.kind == "slsa-provenance"
    assert not report.errors


# ---------------------------------------------------------------------------
# Multi-record release JSONL
# ---------------------------------------------------------------------------


def _release_jsonl(directory: Path, statements: list[dict[str, Any]], name: str) -> Path:
    return _write(
        directory,
        "\n".join(json.dumps(_bundle(s)) for s in statements),
        name=name,
    )


def _release_statement(purl: str, asset: str) -> dict[str, Any]:
    payload = _statement(_RELEASE_V02)
    payload["predicate"]["purl"] = purl
    payload["subject"] = [{"name": asset, "digest": {"sha256": "cafe"}}]
    return payload


def test_jsonl_with_two_release_attestations_yields_both(tmp_path: Path) -> None:
    # A real release publishes an attestation per artifact — an sdist and a
    # wheel, or several npm packages. Keeping only the first loses the rest.
    path = _release_jsonl(
        tmp_path,
        [
            _release_statement("pkg:pypi/demo@1.0.0", "demo-1.0.0.tar.gz"),
            _release_statement("pkg:npm/demo@1.0.0", "demo-1.0.0.tgz"),
        ],
        "releases.jsonl",
    )
    parsed = parse_release_attestations(path)
    assert [p.purl for p in parsed] == ["pkg:pypi/demo@1.0.0", "pkg:npm/demo@1.0.0"]


def test_record_without_purl_is_skipped_but_valid_ones_survive(tmp_path: Path) -> None:
    # One malformed attestation must not take the valid ones down with it.
    broken = _release_statement("pkg:pypi/broken@1.0.0", "broken.tar.gz")
    del broken["predicate"]["purl"]
    path = _release_jsonl(
        tmp_path,
        [broken, _release_statement("pkg:pypi/good@1.0.0", "good.tar.gz")],
        "mixed.jsonl",
    )
    parsed = parse_release_attestations(path)
    assert [p.purl for p in parsed] == ["pkg:pypi/good@1.0.0"]


def test_all_records_missing_purl_still_raises(tmp_path: Path) -> None:
    broken = _release_statement("pkg:pypi/broken@1.0.0", "broken.tar.gz")
    del broken["predicate"]["purl"]
    path = _release_jsonl(tmp_path, [broken, broken], "allbroken.jsonl")
    with pytest.raises(ParseError, match="purl"):
        parse_release_attestations(path)


def test_collector_ingests_every_release_attestation(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _release_jsonl(
        artifacts,
        [
            _release_statement("pkg:pypi/demo@1.0.0", "demo-1.0.0.tar.gz"),
            _release_statement("pkg:npm/demo@1.0.0", "demo-1.0.0.tgz"),
        ],
        "releases.jsonl",
    )
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    purls = sorted(e.metadata["purl"] for e in report.evidence)
    assert purls == ["pkg:npm/demo@1.0.0", "pkg:pypi/demo@1.0.0"]
