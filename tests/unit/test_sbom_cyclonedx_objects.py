"""Tests for CycloneDX 1.6/1.7 evidence-object extraction (ML-BOM, CBOM,
declarations/attestations) and its conditional surfacing on SBOM evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sbom
from evidence_collector.parsers.sbom import parse_sbom

CDX_RICH: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.7",
    "metadata": {"component": {"name": "app", "version": "1.0"}},
    "components": [
        {"type": "machine-learning-model", "name": "classifier", "version": "1.0"},
        {"type": "data", "name": "training-set", "version": "1.0"},
        {"type": "cryptographic-asset", "name": "rsa-2048"},
        {"type": "library", "name": "lib", "version": "2.0"},
        "not-a-dict",
    ],
    "declarations": {"attestations": [{"summary": "slsa"}, {"summary": "iso"}, "bad"]},
}

CDX_PLAIN: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [{"type": "library", "name": "lib", "version": "1.0"}],
}

SPDX_PLAIN: dict[str, Any] = {
    "spdxVersion": "SPDX-2.3",
    "name": "app",
    "packages": [{"name": "lib", "SPDXID": "SPDXRef-lib", "versionInfo": "1.0"}],
}


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main")


def _write(tmp_path: Path, payload: dict[str, Any], name: str = "sbom.json") -> Path:
    target = tmp_path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_counts_cyclonedx_evidence_objects(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, CDX_RICH))
    assert parsed.ml_model_count == 1
    assert parsed.dataset_count == 1
    assert parsed.crypto_asset_count == 1
    assert parsed.attestation_count == 2  # the non-dict attestation is skipped


def test_plain_cyclonedx_has_zero_object_counts(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, CDX_PLAIN))
    assert (
        parsed.ml_model_count,
        parsed.dataset_count,
        parsed.crypto_asset_count,
        parsed.attestation_count,
    ) == (0, 0, 0, 0)


def test_spdx_has_zero_object_counts(tmp_path: Path) -> None:
    parsed = parse_sbom(_write(tmp_path, SPDX_PLAIN))
    assert parsed.ml_model_count == 0
    assert parsed.crypto_asset_count == 0


def test_ml_bom_subject_component_is_counted(tmp_path: Path) -> None:
    # A single-model ML-BOM describes the model as the BOM subject in
    # metadata.component, with nothing under components[].
    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"type": "machine-learning-model", "name": "m"}},
        "components": [],
    }
    parsed = parse_sbom(_write(tmp_path, sbom))
    assert parsed.ml_model_count == 1


def test_normalize_surfaces_object_metadata_when_present(tmp_path: Path) -> None:
    ev = normalize_sbom(parse_sbom(_write(tmp_path, CDX_RICH)), _release())
    assert ev.metadata["ml_bom"] == {"model_count": 1, "dataset_count": 1}
    assert ev.metadata["cbom"] == {"cryptographic_asset_count": 1}
    assert ev.metadata["cyclonedx_attestation_count"] == 2


def test_normalize_omits_object_metadata_when_absent(tmp_path: Path) -> None:
    # Critical for byte-stability: a classic dependency SBOM gains no new
    # metadata keys, so pre-1.7 bundles keep the same structural hash.
    ev = normalize_sbom(parse_sbom(_write(tmp_path, CDX_PLAIN)), _release())
    assert "ml_bom" not in ev.metadata
    assert "cbom" not in ev.metadata
    assert "cyclonedx_attestation_count" not in ev.metadata
