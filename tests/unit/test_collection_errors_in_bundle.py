"""A supplied input that could not be read must survive into the bundle.

"No evidence was supplied" and "evidence was supplied and is broken" are
materially different states, and only the first was ever recorded. The
collector warned on the console and the warning died there: bundle.json,
report.md and summary.html all showed the affected control as plainly
*missing evidence*, telling the engineer to re-run a scan that had already
run and whose truncated output was sitting on disk.

CI logs rotate. The bundle is the durable, signable artifact that `verify`,
`compare`, `statement`, `vex` and `oscal` consume, so the distinction has to
live there to survive.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.application.integrity import normalize_bundle
from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.models import Application, ReleaseContext


def _run(tmp_path: Path, artifacts: Path):
    return run_pipeline(
        Application(name="demo", repository="acme/demo"),
        ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890", branch="main"),
        artifacts_dirs=[artifacts],
        output_dir=tmp_path / "out",
    )


def _sarif() -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "semgrep", "version": "1.0.0", "rules": []}},
                    "results": [],
                }
            ],
        }
    )


def test_broken_input_is_recorded_in_the_bundle(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "good.sarif").write_text(_sarif(), encoding="utf-8")
    (artifacts / "truncated.sarif").write_text('{"runs": [ trunc', encoding="utf-8")

    result = _run(tmp_path, artifacts)

    assert len(result.bundle.collection_errors) == 1
    error = result.bundle.collection_errors[0]
    assert error.path.endswith("truncated.sarif")
    assert "Invalid JSON" in error.reason
    # The good artifact still lands, so a broken sibling costs nothing.
    assert len(result.bundle.evidence) == 1


def test_the_broken_input_reaches_report_and_summary(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "truncated.sarif").write_text('{"runs": [ trunc', encoding="utf-8")

    result = _run(tmp_path, artifacts)

    assert result.markdown_path is not None
    assert result.html_path is not None
    markdown = result.markdown_path.read_text(encoding="utf-8")
    html = result.html_path.read_text(encoding="utf-8")
    for rendered in (markdown, html):
        assert "truncated.sarif" in rendered
        # The reader must be told not to trust the gaps below at face value.
        assert "could not be read" in rendered or "could not be read" in rendered.lower()


def test_a_clean_run_records_no_errors_and_stays_byte_stable(tmp_path: Path) -> None:
    """A clean bundle must not carry the field at all.

    Two separate guarantees, and the first was missing. The published schema
    is `additionalProperties: false` at every level, so a consumer validating
    against the 1.0.0 contract they pinned rejects any bundle carrying a field
    that contract does not know — and with the key always present, *every*
    bundle broke them, including the overwhelming majority where nothing had
    gone wrong. Serialization now omits it when empty, so a clean run stays
    byte-identical to what it produced before the field existed.

    The normaliser strips it too, so the structural hash is unaffected either
    way — the same treatment a null `risk_assessment` gets.
    """
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "good.sarif").write_text(_sarif(), encoding="utf-8")

    result = _run(tmp_path, artifacts)
    assert result.bundle.collection_errors == []

    payload = json.loads(result.bundle.model_dump_json(exclude_none=False))
    assert "collection_errors" not in payload
    normalized = normalize_bundle(payload)
    assert b"collection_errors" not in normalized


def test_a_run_with_errors_does_change_the_structural_hash(tmp_path: Path) -> None:
    """...but a bundle that DID record a broken input must hash differently.

    That is the point: the two runs describe different states of the world.
    """
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "good.sarif").write_text(_sarif(), encoding="utf-8")
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "good.sarif").write_text(_sarif(), encoding="utf-8")
    (broken / "truncated.sarif").write_text('{"runs": [ trunc', encoding="utf-8")

    clean_bundle = _run(tmp_path / "a", clean).bundle
    broken_bundle = _run(tmp_path / "b", broken).bundle

    clean_norm = normalize_bundle(json.loads(clean_bundle.model_dump_json(exclude_none=False)))
    broken_norm = normalize_bundle(json.loads(broken_bundle.model_dump_json(exclude_none=False)))
    assert b"collection_errors" in broken_norm
    assert clean_norm != broken_norm


def test_a_long_path_or_reason_is_clipped_instead_of_ending_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`CollectionError` caps `path` at 500 characters and `reason` at 1000.

    A deep path is legal on Linux and a parser's message can run long. Either
    one made the model raise while the bundle was being built, which ended
    `run` before any report was written: the failure this record exists to
    survive. The tail of a path and the head of a reason carry the useful part,
    so that is what is kept.
    """
    from evidence_collector.collectors import local

    long_path = Path("deep", *(["d" * 50] * 12), "report.sarif")
    long_reason = "Invalid JSON in report.sarif: " + "x" * 1500
    original = local.LocalArtifactCollector.collect

    def collect_with_a_long_error(
        self: local.LocalArtifactCollector,
    ) -> local.LocalCollectionReport:
        report = original(self)
        report.errors.append(local.LocalCollectionError(path=long_path, reason=long_reason))
        return report

    monkeypatch.setattr(local.LocalArtifactCollector, "collect", collect_with_a_long_error)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()

    result = _run(tmp_path, artifacts)

    assert result.json_path is not None and result.json_path.is_file()
    [error] = result.bundle.collection_errors
    assert len(error.path) <= 500
    assert error.path.endswith("report.sarif")
    assert len(error.reason) <= 1000
    assert error.reason.startswith("Invalid JSON in report.sarif")
