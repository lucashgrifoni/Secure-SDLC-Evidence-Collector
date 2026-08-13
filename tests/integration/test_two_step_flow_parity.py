"""`collect` → `evaluate` must reach the same verdict as `run`.

The README presents both as first-class ways to produce a bundle, but two
options existed only on `run`:

- `--artifact-root`, so the two-step flow could not strip local paths at all
  and always wrote absolute filesystem locations into the published bundle;
- `--exceptions-dir`, so it could not apply a waiver — a control `run` reports
  as WAIVED came out MISSING, and the same evidence with the same approved,
  in-force exception produced two different release verdicts depending on
  which documented path the operator took.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from evidence_collector.cli.main import app

_WAIVER = """exception_id: EXC-2026-DEMO-001
control_id: SSDF-PW.1
approver: appsec-lead@example.com
approved_at: "2026-01-01T00:00:00Z"
expires_at: "2036-01-01T00:00:00Z"
justification: No new trust boundary; follow-up scheduled for next quarter.
"""


def _waivers(tmp_path: Path) -> Path:
    directory = tmp_path / "waivers"
    directory.mkdir()
    (directory / "EXC-2026-DEMO-001.yaml").write_text(_WAIVER, encoding="utf-8")
    return directory


def _bundle(output_dir: Path) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((output_dir / "bundle.json").read_text(encoding="utf-8"))
    return payload


def _waived(bundle: dict[str, Any]) -> list[str]:
    return [
        item["control_id"]
        for item in bundle["control_evaluations"]
        if item["evaluation_status"] == "waived"
    ]


def test_the_two_step_flow_applies_waivers_like_run(
    tmp_path: Path, sample_release_root: Path
) -> None:
    runner = CliRunner()
    waivers = _waivers(tmp_path)
    common = [
        "--release-id",
        "1.0.0",
        "--commit-sha",
        "abcdef1234567890",
    ]

    one_step = tmp_path / "one-step"
    runner.invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            *common,
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--exceptions-dir",
            str(waivers),
            "--output-dir",
            str(one_step),
        ],
    )

    evidence = tmp_path / "evidence.json"
    runner.invoke(
        app,
        [
            "collect",
            *common,
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--output",
            str(evidence),
        ],
    )
    two_step = tmp_path / "two-step"
    runner.invoke(
        app,
        [
            "evaluate",
            "--evidence",
            str(evidence),
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            *common,
            "--exceptions-dir",
            str(waivers),
            "--output-dir",
            str(two_step),
        ],
    )

    assert _waived(_bundle(one_step)) == ["SSDF-PW.1"]
    assert _waived(_bundle(two_step)) == _waived(_bundle(one_step))
    assert (
        _bundle(two_step)["summary"]["release_status"]
        == _bundle(one_step)["summary"]["release_status"]
    )


def test_collect_can_strip_local_paths(tmp_path: Path, sample_release_root: Path) -> None:
    """Without `--artifact-root` here, the two-step flow leaked every path."""
    evidence = tmp_path / "evidence.json"

    CliRunner().invoke(
        app,
        [
            "collect",
            "--release-id",
            "1.0.0",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--artifact-root",
            str(sample_release_root),
            "--output",
            str(evidence),
        ],
    )

    payload = json.loads(evidence.read_text(encoding="utf-8"))
    recorded = [item["raw"]["artifact_path"] for item in payload["evidence"] if item.get("raw")]
    assert recorded, "the sample release should have produced evidence with raw refs"
    for path in recorded:
        assert not Path(path).is_absolute(), path
        assert str(sample_release_root) not in path
