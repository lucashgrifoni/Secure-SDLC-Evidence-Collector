"""Control catalog and evaluation engine.

The `controls` package is responsible for:
- loading the initial control catalog shipped with the product,
- evaluating each control against a collected evidence set,
- producing structured gaps and rationales.
"""

from __future__ import annotations

from evidence_collector.controls.catalog import default_catalog, load_catalog
from evidence_collector.controls.engine import evaluate_controls

__all__ = ["default_catalog", "evaluate_controls", "load_catalog"]
