"""Model Card parser (Hugging Face / Google Model Card Toolkit shapes).

Two JSON shapes are commonly exported for model cards:

1. **Hugging Face Hub metadata** — the ``README.md`` YAML frontmatter
   serialised to JSON (or via the ``huggingface_hub`` Python API). Top
   level carries ``model_name``, ``license``, ``datasets``,
   ``model-index[*].results[*].metrics``.

2. **Google Model Card Toolkit (MCT)** — proto-shaped JSON with
   ``model_details``, ``considerations``, ``quantitative_analysis``.
   ``model_details.name`` carries the identifier and
   ``quantitative_analysis.performance_metrics`` carries metrics.

We support both shapes by sniffing the discriminating top-level
keys. Output is a flat ``ParsedModelCard`` so the normalizer can map
to ``MODEL_CARD`` evidence regardless of source shape.

Spec references
* Hugging Face Model Card YAML: https://huggingface.co/docs/hub/model-cards
* Google Model Card Toolkit: https://github.com/tensorflow/model-card-toolkit
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
    load_json,
)

ModelCardShape = Literal["huggingface", "google-mct", "generic"]


@dataclass
class ParsedModelCard:
    artifact: ParsedArtifact
    shape: ModelCardShape
    model_id: str | None = None
    license: str | None = None
    datasets: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    intended_use: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _detect_shape(data: dict[str, Any]) -> ModelCardShape:
    if isinstance(data.get("model_details"), dict):
        return "google-mct"
    # HF model cards expose model_name + license/datasets at the top.
    if isinstance(data.get("model_name") or data.get("model_id"), str):
        return "huggingface"
    if isinstance(data.get("model-index"), list):
        return "huggingface"
    return "generic"


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v]
    if isinstance(value, str) and value:
        return [value]
    return []


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _parse_huggingface(data: dict[str, Any]) -> ParsedModelCard:
    model_id_raw = data.get("model_id") or data.get("model_name") or data.get("base_model")
    license_raw = data.get("license")
    datasets = _coerce_string_list(data.get("datasets"))
    intended_use_raw = data.get("intended_use") or data.get("description")

    metrics: dict[str, float] = {}
    model_index = data.get("model-index")
    if isinstance(model_index, list):
        for entry in model_index:
            if not isinstance(entry, dict):
                continue
            results = entry.get("results")
            if not isinstance(results, list):
                continue
            for result in results:
                if not isinstance(result, dict):
                    continue
                for metric in result.get("metrics", []) or []:
                    if not isinstance(metric, dict):
                        continue
                    name = metric.get("name") or metric.get("type")
                    value = _coerce_float(metric.get("value"))
                    if isinstance(name, str) and name and value is not None:
                        metrics[name] = value

    return ParsedModelCard(
        artifact=ParsedArtifact(Path(), "", 0, ""),  # filled in by caller
        shape="huggingface",
        model_id=str(model_id_raw) if model_id_raw else None,
        license=str(license_raw) if license_raw else None,
        datasets=datasets,
        metrics=metrics,
        intended_use=str(intended_use_raw) if intended_use_raw else None,
        raw=data,
    )


def _parse_google_mct(data: dict[str, Any]) -> ParsedModelCard:
    details = data.get("model_details", {}) if isinstance(data, dict) else {}
    if not isinstance(details, dict):
        details = {}
    model_id_raw = details.get("name")
    license_raw = None
    licenses = details.get("licenses")
    if isinstance(licenses, list) and licenses:
        first = licenses[0]
        if isinstance(first, dict):
            license_raw = first.get("identifier") or first.get("custom_text")
        elif isinstance(first, str):
            license_raw = first

    datasets: list[str] = []
    considerations = data.get("considerations")
    if isinstance(considerations, dict):
        # Considerations sometimes carry dataset references in `use_cases`.
        for entry in considerations.get("use_cases", []) or []:
            if isinstance(entry, dict):
                desc = entry.get("description")
                if isinstance(desc, str) and desc:
                    datasets.append(desc)

    metrics: dict[str, float] = {}
    qa = data.get("quantitative_analysis")
    if isinstance(qa, dict):
        for entry in qa.get("performance_metrics", []) or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("type")
            value = _coerce_float(entry.get("value"))
            if isinstance(name, str) and name and value is not None:
                metrics[name] = value

    intended_use_raw = None
    if isinstance(considerations, dict):
        intended_use_list = considerations.get("use_cases")
        if isinstance(intended_use_list, list) and intended_use_list:
            first = intended_use_list[0]
            if isinstance(first, dict):
                intended_use_raw = first.get("description")
            elif isinstance(first, str):
                intended_use_raw = first

    return ParsedModelCard(
        artifact=ParsedArtifact(Path(), "", 0, ""),  # filled in by caller
        shape="google-mct",
        model_id=str(model_id_raw) if model_id_raw else None,
        license=str(license_raw) if license_raw else None,
        datasets=datasets,
        metrics=metrics,
        intended_use=str(intended_use_raw) if intended_use_raw else None,
        raw=data,
    )


def parse_model_card(path: str | Path) -> ParsedModelCard:
    resolved = ensure_file(path)
    data = load_json(resolved)
    shape = _detect_shape(data)
    if shape == "huggingface":
        parsed = _parse_huggingface(data)
    elif shape == "google-mct":
        parsed = _parse_google_mct(data)
    else:
        raise ParseError(
            f"Model card {resolved} did not match Hugging Face or Google MCT shape "
            "(no ``model_details``, ``model_name``, or ``model-index`` at the top level)."
        )
    artifact = describe(resolved, content_type="application/json")
    parsed.artifact = artifact
    return parsed
