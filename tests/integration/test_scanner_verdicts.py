"""End to end: what real scanner output does to the release verdict.

Each case copies the sample release, swaps in one scanner file, and runs
`run --fail-on conditional`, which is how the publish workflow gates the
sample. The unchanged sample stays ready with exit 0.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from evidence_collector.cli.main import app

REAL = Path(__file__).resolve().parents[1] / "fixtures" / "real"

_FAILED_INVOCATION: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "semgrep", "semanticVersion": "1.70.0"}},
            "invocations": [
                {
                    "executionSuccessful": False,
                    "exitCode": 2,
                    "toolExecutionNotifications": [
                        {"level": "error", "message": {"text": "Fatal: could not parse project"}}
                    ],
                }
            ],
            "results": [],
        }
    ],
}


def _run(
    tmp_path: Path, sample_release_root: Path, swap: dict[str, Path | dict[str, Any]]
) -> tuple[Any, dict[str, Any], dict[str, str]]:
    artifacts = tmp_path / "artifacts"
    shutil.copytree(sample_release_root / "artifacts", artifacts)
    for name, source in swap.items():
        target = artifacts / name
        if isinstance(source, Path):
            shutil.copy(source, target)
        else:
            target.write_text(json.dumps(source), encoding="utf-8")
    out = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(artifacts),
            "--attestations-dir",
            str(sample_release_root / "attestations"),
            "--output-dir",
            str(out),
            "--fail-on",
            "conditional",
        ],
    )
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    controls = {c["control_id"]: c["evaluation_status"] for c in bundle["control_evaluations"]}
    return result, bundle, controls


@pytest.mark.integration
def test_unchanged_sample_stays_ready(tmp_path: Path, sample_release_root: Path) -> None:
    result, bundle, _ = _run(tmp_path, sample_release_root, {})
    assert result.exit_code == 0, result.output
    assert bundle["summary"]["release_status"] == "ready"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("swap", "control", "evidence_status"),
    [
        # Real Semgrep 1.179.0: an ERROR rule hit with no result level.
        ({"semgrep.sarif": REAL / "semgrep" / "semgrep.sarif"}, "SSDF-PW.7", "failed"),
        # A run that reports it did not complete.
        ({"semgrep.sarif": _FAILED_INVOCATION}, "SSDF-PW.7", "invalid"),
        # Real Gitleaks 8.30.1 with one detected secret at warning level.
        ({"gitleaks.sarif": REAL / "gitleaks" / "leak.sarif"}, "ORG-SECRETS-SCAN", "failed"),
    ],
    ids=["semgrep-rule-default-error", "failed-invocation", "gitleaks-leak"],
)
def test_scanner_output_that_should_block_does(
    tmp_path: Path,
    sample_release_root: Path,
    swap: dict[str, Path | dict[str, Any]],
    control: str,
    evidence_status: str,
) -> None:
    result, bundle, controls = _run(tmp_path, sample_release_root, swap)
    assert result.exit_code == 1, result.output
    assert bundle["summary"]["release_status"] == "conditional"
    assert controls[control] == "missing"
    (name,) = swap
    statuses = {e["status"] for e in bundle["evidence"] if e["raw"]["artifact_path"].endswith(name)}
    assert statuses == {evidence_status}
