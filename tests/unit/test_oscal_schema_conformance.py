r"""OSCAL output validates against the official NIST OSCAL 1.1.2 JSON schemas.

The schemas live in ``tests/fixtures/oscal`` (see the NOTICE there for the
source and digests). They use Unicode property escapes (``\p{L}``) that
Python's ``re`` rejects, so the ``pattern`` keyword is checked with the
``regex`` package; every other keyword uses the stock Draft 7 validator.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import regex
from jsonschema import validators
from jsonschema.exceptions import ValidationError

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.models import Application, EvidenceBundle, ReleaseContext
from evidence_collector.exporters.oscal import export_oscal_assessment_results

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "oscal"


def _pattern(
    validator: Any, pattern: str, instance: Any, schema: dict[str, Any]
) -> Iterator[ValidationError]:
    if validator.is_type(instance, "string") and not regex.search(pattern, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_OscalValidator = validators.extend(  # type: ignore[no-untyped-call]
    jsonschema.Draft7Validator, {"pattern": _pattern}
)


def _validator(schema_file: str) -> Any:
    schema = json.loads((FIXTURES / schema_file).read_text(encoding="utf-8"))
    return _OscalValidator(schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)


def _errors(validator: Any, document: dict[str, Any]) -> list[str]:
    return [
        f"{'/'.join(map(str, error.absolute_path))}: {error.message}"
        for error in validator.iter_errors(document)
    ]


@pytest.fixture(scope="module")
def sample_results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    sample = root / "examples" / "sample_release"
    output = tmp_path_factory.mktemp("oscal-sample")
    run_pipeline(
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        artifacts_dirs=[sample / "artifacts"],
        attestations_dirs=[sample / "attestations"],
        exceptions_dirs=[sample / "exceptions"],
        output_dir=output,
        artifact_root=root,
    )
    bundle = EvidenceBundle.model_validate_json(
        (output / "bundle.json").read_text(encoding="utf-8")
    )
    return export_oscal_assessment_results(bundle)


def _embedded_plan(results: dict[str, Any]) -> dict[str, Any]:
    ar = results["assessment-results"]
    resources = {r["uuid"]: r for r in ar["back-matter"]["resources"]}
    resource = resources[ar["import-ap"]["href"].lstrip("#")]
    plan: dict[str, Any] = json.loads(base64.b64decode(resource["base64"]["value"]))
    return plan


def test_sample_assessment_results_validate_against_the_oscal_schema(
    sample_results: dict[str, Any],
) -> None:
    assert _errors(_validator("oscal_assessment-results_schema.json"), sample_results) == []


def test_embedded_assessment_plan_validates_against_the_oscal_schema(
    sample_results: dict[str, Any],
) -> None:
    plan = _embedded_plan(sample_results)
    assert _errors(_validator("oscal_assessment-plan_schema.json"), plan) == []


def test_the_schema_check_rejects_a_broken_document(sample_results: dict[str, Any]) -> None:
    broken = json.loads(json.dumps(sample_results))
    del broken["assessment-results"]["metadata"]["title"]
    broken["assessment-results"]["uuid"] = "not-a-uuid"
    errors = _errors(_validator("oscal_assessment-results_schema.json"), broken)
    assert any("'title' is a required property" in e for e in errors)
    assert any(e.startswith("assessment-results/uuid") for e in errors)
