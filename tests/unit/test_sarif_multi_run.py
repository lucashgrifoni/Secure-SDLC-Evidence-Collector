"""A merged SARIF carries one run per tool, and each is its own evidence.

`parse_sarif` split its contract across two scopes: `runs[0]` supplied the
tool name — the record's identity and the input to the classifier — while the
findings loop aggregated across *every* run. A semgrep+gitleaks+trivy file
therefore produced a single `sast_scan` record attributed to semgrep,
carrying everyone's findings, and the release reported the secrets and SCA
controls as missing critical evidence while both scans had been supplied.

`trivy fs --format sarif` and most aggregators emit exactly that shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.enums import EvidenceType
from evidence_collector.domain.models import ReleaseContext
from evidence_collector.normalizers import normalize_sarif
from evidence_collector.parsers import parse_sarif, parse_sarifs


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="1.0.0", commit_sha="abcdef1234567890", branch="main")


def _run(tool: str, levels: list[str]) -> dict[str, Any]:
    return {
        "tool": {"driver": {"name": tool, "version": "1.0.0", "rules": []}},
        "results": [{"level": level, "ruleId": f"{tool}-rule"} for level in levels],
    }


def _write(directory: Path, runs: list[dict[str, Any]], name: str = "merged.sarif") -> Path:
    target = directory / name
    target.write_text(json.dumps({"version": "2.1.0", "runs": runs}), encoding="utf-8")
    return target


def test_each_run_becomes_its_own_parsed_record(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        [
            _run("semgrep", ["error"]),
            _run("gitleaks", ["error", "warning"]),
            _run("trivy", ["note"]),
        ],
    )
    parsed = parse_sarifs(path)
    assert [p.tool_name for p in parsed] == ["semgrep", "gitleaks", "trivy"]
    # Findings belong to the run that reported them, not to runs[0].
    assert [p.total_findings for p in parsed] == [1, 2, 1]


def test_each_run_is_classified_by_its_own_driver(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _write(artifacts, [_run("semgrep", ["error"]), _run("gitleaks", ["error"])])
    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()
    assert sorted(e.evidence_type for e in report.evidence) == sorted(
        [EvidenceType.SAST_SCAN, EvidenceType.SECRETS_SCAN]
    )
    assert not report.errors


def test_runs_of_the_same_tool_do_not_collide_on_evidence_id(tmp_path: Path) -> None:
    # The id derives from tool name + artifact hash + commit, so two runs of
    # one tool in one file would otherwise produce the same id twice.
    path = _write(tmp_path, [_run("semgrep", ["error"]), _run("semgrep", ["warning"])])
    ids = {normalize_sarif(p, _release()).evidence_id for p in parse_sarifs(path)}
    assert len(ids) == 2


def test_a_single_run_file_keeps_its_previous_evidence_id(tmp_path: Path) -> None:
    """Byte-stability where it matters.

    Every fixture and the overwhelming majority of real SARIF files carry one
    run. Their ids must not move, or the determinism snapshots and any pinned
    `verify --expected` would break for a change that does not affect them.
    """
    path = _write(tmp_path, [_run("semgrep", ["error"])], name="single.sarif")
    parsed = parse_sarifs(path)
    assert len(parsed) == 1
    assert parsed[0].run_index == 0
    # run_index 0 contributes nothing to the id, so the digest input is the
    # same tuple the parser produced before merged files were split.
    assert (
        normalize_sarif(parsed[0], _release()).evidence_id
        == normalize_sarif(parse_sarif(path), _release()).evidence_id
    )


def test_a_run_without_results_still_yields_evidence(tmp_path: Path) -> None:
    # "The scan ran and found nothing" is the control-satisfying case; losing
    # it would understate coverage.
    path = _write(tmp_path, [_run("semgrep", []), _run("gitleaks", [])])
    parsed = parse_sarifs(path)
    assert len(parsed) == 2
    assert all(p.total_findings == 0 for p in parsed)


def test_a_malformed_run_among_valid_ones_is_skipped(tmp_path: Path) -> None:
    target = tmp_path / "mixed.sarif"
    target.write_text(
        json.dumps({"version": "2.1.0", "runs": [_run("semgrep", ["error"]), "not-a-run"]}),
        encoding="utf-8",
    )
    parsed = parse_sarifs(target)
    assert [p.tool_name for p in parsed] == ["semgrep"]
