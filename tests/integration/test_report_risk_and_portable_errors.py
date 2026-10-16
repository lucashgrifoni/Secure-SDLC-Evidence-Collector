"""What the reports say about a risk-weighted verdict, and how errors are recorded.

A run with ``--risk-mode epss-weighted`` kept its rationale only in
``summary.risk_assessment``: report.md, summary.html and the console showed
the verdict with nothing explaining it. And a rejected waiver recorded the
raw pydantic text in ``collection_errors``, with a documentation URL named
after the installed pydantic version and the rejected input quoted, so the
structural digest of the same failure changed with the pydantic release.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app
from evidence_collector.parsers._common import describe_failure, validation_detail

_IDENTITY = [
    "--application",
    "payments-api",
    "--repository",
    "acme/payments-api",
    "--release-id",
    "2026.04.10",
    "--commit-sha",
    "abcdef1234567890",
]


def _run(tmp_path: Path, sample_release_root: Path, *extra: str) -> tuple[int, str, Path]:
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "run",
            *_IDENTITY,
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--output-dir",
            str(out),
            *extra,
        ],
    )
    return result.exit_code, result.output, out


@pytest.mark.integration
def test_reports_explain_a_risk_weighted_verdict(tmp_path: Path, sample_release_root: Path) -> None:
    _, output, out = _run(tmp_path, sample_release_root, "--risk-mode", "epss-weighted")
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    rationale = bundle["summary"]["risk_assessment"]["rationale"]
    assert rationale

    report = (out / "report.md").read_text(encoding="utf-8")
    assert "Risk-weighted verdict" in report
    assert "no EPSS / KEV threshold was applied" in report
    assert "no EPSS / KEV threshold was applied" in (out / "summary.html").read_text(
        encoding="utf-8"
    )
    assert "Risk-weighted" in output


@pytest.mark.integration
def test_reports_without_risk_mode_carry_no_risk_line(
    tmp_path: Path, sample_release_root: Path
) -> None:
    _, _, out = _run(tmp_path, sample_release_root)
    assert "Risk-weighted" not in (out / "report.md").read_text(encoding="utf-8")


@pytest.mark.integration
def test_a_rejected_waiver_is_recorded_without_pydantic_noise(
    tmp_path: Path, sample_release_root: Path
) -> None:
    exceptions = tmp_path / "waivers" / "nested"
    exceptions.mkdir(parents=True)
    # Expiry before approval: the model validator rejects it.
    (exceptions / "inverted.yaml").write_text(
        "exception_id: EXC-INV\n"
        "control_id: SSDF-PW.7\n"
        "approver: security-lead\n"
        "approved_at: 2026-04-10T00:00:00Z\n"
        "expires_at: 2026-04-01T00:00:00Z\n"
        "justification: inverted window\n",
        encoding="utf-8",
    )
    _, _, out = _run(
        tmp_path,
        sample_release_root,
        "--exceptions-dir",
        str(tmp_path / "waivers"),
        "--artifact-root",
        str(tmp_path),
    )
    errors = json.loads((out / "bundle.json").read_text(encoding="utf-8"))["collection_errors"]
    (error,) = errors
    assert error["path"] == "waivers/nested/inverted.yaml"
    assert "waivers/nested/inverted.yaml" in error["reason"]
    assert "errors.pydantic.dev" not in error["reason"]
    assert "input_value" not in error["reason"]
    assert "\n" not in error["reason"]


def test_validation_detail_drops_generated_titles_and_the_value_error_prefix() -> None:
    from pydantic import BaseModel, TypeAdapter, ValidationError, field_validator

    class Model(BaseModel):
        name: str

        @field_validator("name")
        @classmethod
        def _short(cls, value: str) -> str:
            raise ValueError("too long")

    with pytest.raises(ValidationError) as named:
        Model(name="x")
    assert validation_detail(named.value) == "Model.name: too long"

    with pytest.raises(ValidationError) as generated:
        TypeAdapter(list[Model]).validate_python([{"name": "x"}])
    assert validation_detail(generated.value) == "0.name: too long"


def test_describe_failure_flattens_a_multiline_message() -> None:
    assert describe_failure(ValueError("first\nsecond")) == "first second"
    assert describe_failure(ValueError("")) == "ValueError"
