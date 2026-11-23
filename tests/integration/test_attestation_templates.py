"""The attestation templates in examples/attestations/ behave as their README says.

Shipped as they are, they satisfy nothing (`status: unknown`), so the sample
scanner output stays `not_ready`; filled in with `status: passed` they make it
`ready`. Their placeholders must not look like a real secret, host or person,
because people copy them into their own repositories.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import Application, ReleaseContext, Summary

TEMPLATES = Path(__file__).resolve().parents[2] / "examples" / "attestations"

CRITICAL_FROM_ATTESTATIONS = {
    "ORG-CODE-REVIEW:code_review",
    "ORG-RELEASE-APPROVAL:release_approval",
    "ORG-REL-ROLLBACK:rollback_plan",
    "SSDF-PS.2:artifact_signature",
}

# Specification identifiers, not hosts anyone is asked to contact.
STANDARD_URIS = {
    "https://slsa.dev/provenance/v1",
    "https://token.actions.githubusercontent.com",
}
# RFC 2606 and RFC 6761 names reserved for documentation.
RESERVED_DOMAIN = re.compile(r"(^|\.)(example\.(com|org|net)|example|test|invalid)$")
EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
URL = re.compile(r"https?://([^/\s\"']+)")
SECRET_SHAPES = re.compile(
    r"ghp_|gho_|github_pat_|glpat-|AKIA[0-9A-Z]{12}|xox[abprs]-|-----BEGIN|[A-Za-z0-9+=_-]{32,}"
)
TOOL_PRODUCERS = {"cosign"}


def _templates() -> list[Path]:
    return sorted(TEMPLATES.glob("*.yaml"))


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _summary(attestations_dir: Path, sample_release_root: Path, tmp_path: Path) -> Summary:
    result = run_pipeline(
        application=Application(name="example-app", repository="example-org/example-app"),
        release=ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890"),
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[attestations_dir],
        output_dir=tmp_path / "out",
    )
    assert not result.bundle.collection_errors
    return result.bundle.summary


def test_every_template_ships_with_status_unknown() -> None:
    templates = _templates()
    assert len(templates) == 7
    for template in templates:
        assert yaml.safe_load(template.read_text(encoding="utf-8"))["status"] == "unknown", template


@pytest.mark.integration
def test_templates_as_shipped_leave_the_release_not_ready(
    sample_release_root: Path, tmp_path: Path
) -> None:
    summary = _summary(TEMPLATES, sample_release_root, tmp_path)

    assert summary.release_status == ReleaseStatus.NOT_READY
    assert set(summary.missing_critical_evidence) == CRITICAL_FROM_ATTESTATIONS


@pytest.mark.integration
def test_templates_with_status_passed_make_the_release_ready(
    sample_release_root: Path, tmp_path: Path
) -> None:
    filled = tmp_path / "attestations"
    filled.mkdir()
    for template in _templates():
        text = template.read_text(encoding="utf-8")
        assert text.count("\nstatus: unknown\n") == 1, template
        (filled / template.name).write_text(
            text.replace("\nstatus: unknown\n", "\nstatus: passed\n"), encoding="utf-8"
        )

    summary = _summary(filled, sample_release_root, tmp_path)

    assert summary.release_status == ReleaseStatus.READY
    assert summary.controls_missing == 0


@pytest.mark.parametrize("template", _templates(), ids=lambda path: path.name)
def test_placeholders_name_no_real_secret_host_or_person(template: Path) -> None:
    document = yaml.safe_load(template.read_text(encoding="utf-8"))
    problems: list[str] = []
    for text in _strings(document):
        if SECRET_SHAPES.search(text):
            problems.append(f"looks like a secret: {text!r}")
        if text in STANDARD_URIS:
            continue
        for domain in EMAIL.findall(text) + URL.findall(text):
            if not RESERVED_DOMAIN.search(domain.lower()):
                problems.append(f"not a reserved example domain: {domain!r} in {text!r}")
    producer = document["producer"]
    if producer not in TOOL_PRODUCERS and not producer.startswith("Example "):
        problems.append(f"producer is not an obvious placeholder: {producer!r}")
    assert not problems, "\n".join(problems)
