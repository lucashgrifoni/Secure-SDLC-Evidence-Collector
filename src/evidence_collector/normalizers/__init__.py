"""Normalizers that turn parsed artifacts into NormalizedEvidence records."""

from __future__ import annotations

from evidence_collector.normalizers.engine import (
    normalize_attestation,
    normalize_croissant,
    normalize_garak,
    normalize_intoto_statement,
    normalize_junit,
    normalize_lm_eval,
    normalize_model_card,
    normalize_osv,
    normalize_pr_metadata,
    normalize_provenance,
    normalize_registry_attestation,
    normalize_release_attestation,
    normalize_sarif,
    normalize_sbom,
    normalize_trivy_json,
    normalize_vsa,
    normalize_workflow_run,
    normalize_zap,
)

__all__ = [
    "normalize_attestation",
    "normalize_croissant",
    "normalize_garak",
    "normalize_intoto_statement",
    "normalize_junit",
    "normalize_lm_eval",
    "normalize_model_card",
    "normalize_osv",
    "normalize_pr_metadata",
    "normalize_provenance",
    "normalize_registry_attestation",
    "normalize_release_attestation",
    "normalize_sarif",
    "normalize_sbom",
    "normalize_trivy_json",
    "normalize_vsa",
    "normalize_workflow_run",
    "normalize_zap",
]
