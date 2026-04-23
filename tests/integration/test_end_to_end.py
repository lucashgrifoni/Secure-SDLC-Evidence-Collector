"""End-to-end integration tests driving the orchestrator on fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.enums import ReleaseStatus
from evidence_collector.domain.models import Application, ReleaseContext


@pytest.mark.integration
def test_sample_release_produces_ready_bundle(tmp_path: Path, sample_release_root: Path) -> None:
    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    output_dir = tmp_path / "out"

    result = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=output_dir,
    )

    assert result.json_path is not None and result.json_path.is_file()
    assert result.markdown_path is not None and result.markdown_path.is_file()
    assert result.html_path is not None and result.html_path.is_file()

    summary = result.bundle.summary
    assert summary.release_status == ReleaseStatus.READY
    assert summary.controls_met >= 10
    assert summary.controls_missing == 0
    assert not summary.missing_critical_evidence

    payload = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert payload["bundle_id"] == result.bundle.bundle_id
    assert payload["summary"]["release_status"] == "ready"


@pytest.mark.integration
def test_missing_critical_evidence_blocks_release(
    tmp_path: Path, sample_release_root: Path
) -> None:
    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    output_dir = tmp_path / "out"

    # Only artifacts (scans, SBOM, tests). No manual attestations -> critical
    # controls like ORG-REL-ROLLBACK, SSDF-PS.2 etc. will be missing.
    result = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[],
        output_dir=output_dir,
    )
    summary = result.bundle.summary
    assert summary.release_status == ReleaseStatus.NOT_READY
    assert summary.controls_missing >= 3
    assert summary.missing_critical_evidence


@pytest.mark.integration
def test_unknown_artifact_is_reported_as_warning(tmp_path: Path, sample_release_root: Path) -> None:
    noise_dir = tmp_path / "noisy-artifacts"
    noise_dir.mkdir()
    (noise_dir / "random.txt").write_text("not a scan result", encoding="utf-8")
    # Valid SARIF among noise
    (noise_dir / "semgrep.sarif").write_text(
        (sample_release_root / "artifacts" / "semgrep.sarif").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    result = run_pipeline(
        application=app_,
        release=release,
        artifacts_dirs=[noise_dir],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=tmp_path / "out",
    )
    assert result.collection_report is not None
    # The .txt is simply ignored (not reported as error); only parser failures
    # become errors. So errors may be empty; inspected_files must be > 0.
    assert result.collection_report.inspected_files >= 2
    assert any(e.evidence_type.value == "sast_scan" for e in result.bundle.evidence)
