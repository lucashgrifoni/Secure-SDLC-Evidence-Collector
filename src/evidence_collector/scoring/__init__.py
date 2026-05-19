"""Scoring engine: coverage score, confidence score, release status."""

from __future__ import annotations

from evidence_collector.scoring.engine import build_summary, compute_release_status
from evidence_collector.scoring.risk import (
    DEFAULT_EPSS_PERCENTILE_THRESHOLD,
    RiskMode,
    RiskThresholds,
    apply_risk_mode,
)

__all__ = [
    "DEFAULT_EPSS_PERCENTILE_THRESHOLD",
    "RiskMode",
    "RiskThresholds",
    "apply_risk_mode",
    "build_summary",
    "compute_release_status",
]
