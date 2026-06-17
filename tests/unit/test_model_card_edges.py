"""Edge and error-path tests for the model card parser.

Happy paths for both supported shapes live in ``test_ai_parsers.py``.
These tests pin the defensive branches: shape detection via
``model-index`` alone, scalar/string coercions, and the malformed-entry
skips inside the Hugging Face and Google MCT extraction paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.parsers.model_card import parse_model_card


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    target = tmp_path / "model-card.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_model_card_detected_by_model_index_only(tmp_path: Path) -> None:
    # No model_name/model_id, but a model-index list still routes to the
    # Hugging Face shape. A scalar ``datasets`` string is coerced to a
    # one-element list; bool and non-numeric metric values are dropped.
    path = _write(
        tmp_path,
        {
            "license": "mit",
            "datasets": "single-corpus",
            "model-index": [
                "not-a-dict",
                {"results": "not-a-list"},
                {
                    "results": [
                        "not-a-dict-result",
                        {
                            "metrics": [
                                "not-a-dict-metric",
                                {"name": "accuracy", "value": "0.91"},
                                {"name": "f1", "value": True},
                                {"name": "weird", "value": "not-a-number"},
                            ]
                        },
                    ]
                },
            ],
        },
    )
    parsed = parse_model_card(path)
    assert parsed.shape == "huggingface"
    assert parsed.model_id is None
    assert parsed.license == "mit"
    assert parsed.datasets == ["single-corpus"]
    assert parsed.metrics == {"accuracy": pytest.approx(0.91)}
    assert parsed.intended_use is None


def test_parse_model_card_mct_string_license_and_use_case(tmp_path: Path) -> None:
    # A string (not dict) first license entry, a string first use-case, and
    # use-case entries that carry no description.
    path = _write(
        tmp_path,
        {
            "model_details": {"name": "m1", "licenses": ["BSD-3-Clause"]},
            "considerations": {
                "use_cases": ["Primary screening assistant", {"no_description": "x"}]
            },
        },
    )
    parsed = parse_model_card(path)
    assert parsed.shape == "google-mct"
    assert parsed.model_id == "m1"
    assert parsed.license == "BSD-3-Clause"
    assert parsed.datasets == []
    assert parsed.metrics == {}
    assert parsed.intended_use == "Primary screening assistant"


def test_parse_model_card_mct_handles_missing_and_malformed_sections(tmp_path: Path) -> None:
    # No licenses, considerations that are not a dict, and a metrics list
    # mixing a non-dict entry, an unparseable value, and an empty name.
    path = _write(
        tmp_path,
        {
            "model_details": {"name": "m2"},
            "considerations": "not-a-dict",
            "quantitative_analysis": {
                "performance_metrics": [
                    "not-a-dict",
                    {"type": "precision", "value": 0.8},
                    {"type": "recall", "value": "bad"},
                    {"type": "", "value": 0.5},
                ]
            },
        },
    )
    parsed = parse_model_card(path)
    assert parsed.shape == "google-mct"
    assert parsed.model_id == "m2"
    assert parsed.license is None
    assert parsed.datasets == []
    assert parsed.intended_use is None
    assert parsed.metrics == {"precision": pytest.approx(0.8)}
