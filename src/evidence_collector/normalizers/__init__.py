"""Normalizers that turn parsed artifacts into NormalizedEvidence records."""

from __future__ import annotations

from evidence_collector.normalizers.engine import (
    normalize_attestation,
    normalize_garak,
    normalize_junit,
    normalize_lm_eval,
    normalize_model_card,
    normalize_osv,
    normalize_pr_metadata,
    normalize_sarif,
    normalize_sbom,
    normalize_workflow_run,
    normalize_zap,
)

__all__ = [
    "normalize_attestation",
    "normalize_garak",
    "normalize_junit",
    "normalize_lm_eval",
    "normalize_model_card",
    "normalize_osv",
    "normalize_pr_metadata",
    "normalize_sarif",
    "normalize_sbom",
    "normalize_workflow_run",
    "normalize_zap",
]
