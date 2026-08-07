"""Tests for the package-registry attestation parser (PyPI PEP 740, npm).

Fixture shapes follow the real payloads: the PyPI ones from PEP 740's own
appendix, the npm one from the live shape of
``registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>`` — an
``attestations[]`` array whose ``bundle`` is a Sigstore bundle carrying a
``dsseEnvelope``.
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
from evidence_collector.normalizers import normalize_registry_attestation
from evidence_collector.parsers import parse_registry_attestation
from evidence_collector.parsers._common import ParseError

_SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"
_PYPI_PUBLISH = "https://docs.pypi.org/attestations/publish/v1"
_NPM_PUBLISH = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2.1.0", commit_sha="abcdef1234567890", branch="main")


def _statement(predicate_type: str, name: str = "demo-2.1.0.tar.gz") -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"sha256": "cafe"}}],
        "predicateType": predicate_type,
        "predicate": {},
    }


def _b64(payload: dict[str, Any]) -> str:
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _pep740_attestation(predicate_type: str = _SLSA_PROVENANCE) -> dict[str, Any]:
    return {
        "version": 1,
        "verification_material": {"certificate": "AAAA", "transparency_entries": [{"logIndex": 1}]},
        "envelope": {"statement": _b64(_statement(predicate_type)), "signature": "BBBB"},
    }


def _pypi_provenance() -> dict[str, Any]:
    return {
        "version": 1,
        "attestation_bundles": [
            {
                "publisher": {
                    "kind": "GitHub",
                    "claims": {"ref": "refs/tags/v2.1.0", "sha": "abc"},
                    "repository_name": "demo",
                    "repository_owner": "acme",
                    "workflow_filename": "release.yml",
                },
                "attestations": [
                    _pep740_attestation(_SLSA_PROVENANCE),
                    _pep740_attestation(_PYPI_PUBLISH),
                ],
            }
        ],
    }


def _npm_bundle(predicate_type: str) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}},
        "dsseEnvelope": {
            "payloadType": "application/vnd.in-toto+json",
            "payload": _b64(_statement(predicate_type)),
            "signatures": [{"sig": "AAAA"}],
        },
    }


def _npm_attestations() -> dict[str, Any]:
    return {
        "attestations": [
            {"predicateType": _NPM_PUBLISH, "bundle": _npm_bundle(_NPM_PUBLISH)},
            {"predicateType": _SLSA_PROVENANCE, "bundle": _npm_bundle(_SLSA_PROVENANCE)},
        ]
    }


def _write(directory: Path, payload: Any, name: str = "att.json") -> Path:
    target = directory / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# PyPI — PEP 740
# ---------------------------------------------------------------------------


def test_pypi_provenance_records_publisher_and_predicates(tmp_path: Path) -> None:
    parsed = parse_registry_attestation(_write(tmp_path, _pypi_provenance()))
    assert parsed.registry == "pypi"
    assert parsed.publisher_kind == "GitHub"
    assert [s.predicate_type for s in parsed.statements] == [_SLSA_PROVENANCE, _PYPI_PUBLISH]
    assert parsed.statements[0].subject_name == "demo-2.1.0.tar.gz"


def test_pypi_publisher_kind_is_an_open_string(tmp_path: Path) -> None:
    # PEP 740 defines `kind` as a free string; a registry adding a new
    # publisher type must not break ingestion.
    payload = _pypi_provenance()
    payload["attestation_bundles"][0]["publisher"]["kind"] = "SomeFutureForge"
    parsed = parse_registry_attestation(_write(tmp_path, payload))
    assert parsed.publisher_kind == "SomeFutureForge"


def test_pypi_records_claim_names_not_values(tmp_path: Path) -> None:
    # Claim values are publisher-specific and can carry repository and
    # workflow detail that should not land in a bundle by default.
    parsed = parse_registry_attestation(_write(tmp_path, _pypi_provenance()))
    assert parsed.publisher_claim_keys == ["ref", "sha"]
    ev = normalize_registry_attestation(parsed, _release())
    assert ev.metadata["publisher_claim_keys"] == ["ref", "sha"]
    assert "refs/tags/v2.1.0" not in json.dumps(ev.metadata)


def test_pypi_single_attestation_object(tmp_path: Path) -> None:
    parsed = parse_registry_attestation(_write(tmp_path, _pep740_attestation()))
    assert parsed.registry == "pypi"
    assert [s.predicate_type for s in parsed.statements] == [_SLSA_PROVENANCE]
    assert parsed.publisher_kind is None


def test_pypi_provenance_without_publisher_still_parses(tmp_path: Path) -> None:
    payload = _pypi_provenance()
    del payload["attestation_bundles"][0]["publisher"]
    parsed = parse_registry_attestation(_write(tmp_path, payload))
    assert parsed.publisher_kind is None
    assert len(parsed.statements) == 2


def test_pypi_undecodable_statement_is_rejected(tmp_path: Path) -> None:
    payload = _pep740_attestation()
    payload["envelope"]["statement"] = "not-base64!!!"
    with pytest.raises(ParseError, match="no decodable"):
        parse_registry_attestation(_write(tmp_path, payload))


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def test_npm_attestations_unwrap_the_sigstore_bundles(tmp_path: Path) -> None:
    parsed = parse_registry_attestation(_write(tmp_path, _npm_attestations()))
    assert parsed.registry == "npm"
    assert [s.predicate_type for s in parsed.statements] == [_NPM_PUBLISH, _SLSA_PROVENANCE]


def test_npm_falls_back_to_the_declared_predicate_type(tmp_path: Path) -> None:
    # npm states predicateType alongside the bundle, so a bundle we cannot
    # decode still yields the type it claimed rather than being dropped.
    payload = _npm_attestations()
    payload["attestations"][0]["bundle"] = {"mediaType": "x"}
    parsed = parse_registry_attestation(_write(tmp_path, payload))
    assert [s.predicate_type for s in parsed.statements] == [_NPM_PUBLISH, _SLSA_PROVENANCE]
    assert parsed.statements[0].subject_name is None


def test_npm_decoded_predicate_wins_over_a_disagreeing_declared_one(tmp_path: Path) -> None:
    # `predicateType` sits outside the signature; the Statement inside the
    # DSSE payload is what was actually signed. When they disagree the
    # signed payload must win, or a registry field nobody signed could
    # relabel an attestation.
    payload = {
        "attestations": [
            {"predicateType": "https://example.com/claimed/v1", "bundle": _npm_bundle(_NPM_PUBLISH)}
        ]
    }
    parsed = parse_registry_attestation(_write(tmp_path, payload))
    assert [s.predicate_type for s in parsed.statements] == [_NPM_PUBLISH]


def test_npm_empty_attestations_is_not_claimed(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_registry_attestation(_write(tmp_path, {"attestations": []}))


# ---------------------------------------------------------------------------
# Rejection and normalization
# ---------------------------------------------------------------------------


def test_unrelated_json_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ParseError):
        parse_registry_attestation(_write(tmp_path, {"hello": "world"}))


def test_normalize_registry_attestation(tmp_path: Path) -> None:
    parsed = parse_registry_attestation(_write(tmp_path, _pypi_provenance()))
    ev = normalize_registry_attestation(parsed, _release())
    assert ev.evidence_type == EvidenceType.ARTIFACT_ATTESTATION
    assert ev.status == EvidenceStatus.GENERATED
    assert ev.source.kind == "registry-attestation"
    assert ev.producer == "pypi"
    assert ev.metadata["registry"] == "pypi"
    assert ev.metadata["publisher_kind"] == "GitHub"
    assert ev.metadata["attestation_count"] == 2
    assert ev.metadata["predicate_types"] == sorted([_SLSA_PROVENANCE, _PYPI_PUBLISH])
    assert ev.subject_ref == "demo-2.1.0.tar.gz"


def test_normalize_omits_publisher_when_absent(tmp_path: Path) -> None:
    parsed = parse_registry_attestation(_write(tmp_path, _pep740_attestation()))
    ev = normalize_registry_attestation(parsed, _release())
    assert "publisher_kind" not in ev.metadata


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


def test_collector_ingests_pypi_provenance(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _pypi_provenance(), name="provenance.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [e.source.kind for e in report.evidence] == ["registry-attestation"]
    assert not report.errors


def test_collector_ingests_npm_attestations(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _npm_attestations(), name="npm-attestations.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [e.source.kind for e in report.evidence] == ["registry-attestation"]
    assert report.evidence[0].producer == "npm"


def test_registry_route_does_not_shadow_a_bare_statement(tmp_path: Path) -> None:
    # A raw in-toto Statement must still reach the in-toto routes.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, _statement("https://example.com/unknown/v1"), name="stmt.json")
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert [e.source.kind for e in report.evidence] == ["in-toto-statement"]
