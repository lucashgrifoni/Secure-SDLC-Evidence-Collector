"""Scoring engine: coverage score, confidence score, release status."""

from __future__ import annotations

from evidence_collector.scoring.engine import build_summary, compute_release_status

__all__ = ["build_summary", "compute_release_status"]
