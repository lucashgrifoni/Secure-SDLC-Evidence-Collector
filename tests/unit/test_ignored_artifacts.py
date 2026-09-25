"""A file in --artifacts-dir that no parser claims is reported, not dropped silently.

The collector used to log unrecognised artifacts at debug level only, so a user
who dropped a free-form manifest (a tool list, a hand-written dataset note) next
to the scanner output got no evidence and no word about it. The file is not an
error, so it stays out of ``collection_errors`` and out of the bundle; the
console and the NDJSON stream now say it was not collected.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from evidence_collector.cli.main import app
from evidence_collector.collectors.local import LocalArtifactCollector
from evidence_collector.domain.models import ReleaseContext


def _release() -> ReleaseContext:
    return ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")


def _artifacts(tmp_path: Path, sample_release_root: Path, extra: dict[str, str]) -> Path:
    artifacts = tmp_path / "artifacts"
    shutil.copytree(sample_release_root / "artifacts", artifacts)
    for name, body in extra.items():
        (artifacts / name).write_text(body, encoding="utf-8")
    return artifacts


def _run_args(artifacts: Path, out: Path, sample_release_root: Path) -> list[str]:
    # With the sample attestations the verdict is `ready`, so exit 0 is the
    # only code a correct run can return here.
    attestations = sample_release_root / "attestations"
    return [
        "run",
        "--application",
        "payments-api",
        "--repository",
        "acme/payments-api",
        "--release-id",
        "2026.04.10",
        "--commit-sha",
        "abcdef1234567890",
        "--branch",
        "main",
        "--artifacts-dir",
        str(artifacts),
        "--attestations-dir",
        str(attestations),
        "--output-dir",
        str(out),
    ]


def test_the_collector_lists_files_no_parser_claimed(
    tmp_path: Path, sample_release_root: Path
) -> None:
    artifacts = _artifacts(
        tmp_path,
        sample_release_root,
        {
            "notes.txt": "release notes, not evidence\n",
            "mcp-tools.json": json.dumps({"tools": [{"name": "search"}]}),
            "broken.json": "{not json",
        },
    )

    report = LocalArtifactCollector(_release(), artifacts_dirs=[artifacts]).collect()

    assert sorted(p.name for p in report.ignored) == ["mcp-tools.json", "notes.txt"]
    # A broken JSON file is an error, not an ignored file.
    assert [e.path.name for e in report.errors] == ["broken.json"]
    assert all(p.name not in {"sbom.cdx.json", "semgrep.sarif"} for p in report.ignored)


def test_run_says_which_files_were_not_collected(tmp_path: Path, sample_release_root: Path) -> None:
    artifacts = _artifacts(tmp_path, sample_release_root, {"notes.txt": "hello\n"})
    out = tmp_path / "out"

    result = CliRunner().invoke(app, _run_args(artifacts, out, sample_release_root))

    assert result.exit_code == 0, result.output
    assert "matched no parser" in result.output
    assert "notes.txt" in result.output
    bundle = json.loads((out / "bundle.json").read_text(encoding="utf-8"))
    assert "ignored" not in json.dumps(sorted(bundle))


def test_run_emits_an_ndjson_event_per_ignored_file(
    tmp_path: Path, sample_release_root: Path
) -> None:
    artifacts = _artifacts(tmp_path, sample_release_root, {"notes.txt": "hello\n"})

    result = CliRunner().invoke(
        app, ["--json-logs", *_run_args(artifacts, tmp_path / "out", sample_release_root)]
    )

    assert result.exit_code == 0, result.output
    events = []
    for line in result.output.splitlines():
        if line.strip().startswith("{"):
            events.append(json.loads(line))
    ignored = [e for e in events if e.get("event") == "artifact_ignored"]
    assert [Path(str(e["path"])).name for e in ignored] == ["notes.txt"]


def test_collect_says_which_files_were_not_collected(
    tmp_path: Path, sample_release_root: Path
) -> None:
    artifacts = _artifacts(tmp_path, sample_release_root, {"notes.txt": "hello\n"})
    envelope = tmp_path / "evidence.json"

    result = CliRunner().invoke(
        app,
        [
            "collect",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(artifacts),
            "--output",
            str(envelope),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "matched no parser" in result.output
    assert "notes.txt" in result.output
    assert sorted(json.loads(envelope.read_text(encoding="utf-8"))) == [
        "collection_errors",
        "evidence",
    ]


def test_a_long_list_is_cut_short(tmp_path: Path, sample_release_root: Path) -> None:
    extra = {f"note-{i:02d}.txt": "x\n" for i in range(12)}
    artifacts = _artifacts(tmp_path, sample_release_root, extra)

    result = CliRunner().invoke(app, _run_args(artifacts, tmp_path / "out", sample_release_root))

    assert result.exit_code == 0, result.output
    assert "12 files in --artifacts-dir matched no parser" in result.output
    assert "note-00.txt" in result.output
    assert "note-11.txt" not in result.output
    assert "and 2 more" in result.output
