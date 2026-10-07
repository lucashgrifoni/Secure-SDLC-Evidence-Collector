"""Exercise the installed entrypoint's streams, schema checks and exit codes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from evidence_collector.application.integrity import structural_sha256
from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.models import Application, ReleaseContext

pytestmark = pytest.mark.integration


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "evidence_collector.cli.main", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.fixture
def bundle_file(tmp_path: Path, sample_release_root: Path) -> Path:
    result = run_pipeline(
        application=Application(name="example", repository="acme/example"),
        release=ReleaseContext(release_id="1", commit_sha="abcdef1234567890", branch="main"),
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=tmp_path / "bundle",
    )
    assert result.json_path is not None
    return result.json_path


@pytest.mark.parametrize("payload", [{}, [], None, {"bundle_id": "incomplete"}])
def test_verify_rejects_json_that_is_not_a_bundle(tmp_path: Path, payload: object) -> None:
    source = tmp_path / "arbitrary.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    result = _run("verify", str(source))
    assert result.returncode == 3
    assert result.stdout == ""
    assert "schema" in result.stderr.lower()


@pytest.mark.parametrize("pin", ["", "invalid", "a" * 63, "a" * 65, "g" * 64])
def test_verify_rejects_malformed_pins_as_input_errors(bundle_file: Path, pin: str) -> None:
    result = _run("verify", str(bundle_file), "--expected", pin)
    assert result.returncode == 3
    assert result.stdout == ""
    assert "--expected" in result.stderr


def test_verify_preserves_digest_match_and_drift(bundle_file: Path) -> None:
    digest = structural_sha256(bundle_file)
    assert _run("verify", str(bundle_file)).stdout.strip() == digest
    assert _run("verify", str(bundle_file), "--expected", digest.upper()).returncode == 0
    assert _run("verify", str(bundle_file), "--expected", "0" * 64).returncode == 2


@pytest.mark.parametrize(
    "command",
    [
        "collect",
        "controls",
        "compare",
        "exceptions-list",
        "exceptions-validate",
        "doctor",
        "plugins",
    ],
)
def test_json_logs_are_one_event_per_stdout_line(
    command: str, bundle_file: Path, tmp_path: Path, sample_release_root: Path
) -> None:
    exceptions = sample_release_root / "exceptions"
    args = {
        "collect": [
            "collect",
            "--release-id",
            "1",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--output",
            str(tmp_path / "evidence.json"),
        ],
        "controls": ["controls"],
        "compare": ["compare", str(bundle_file), str(bundle_file)],
        "exceptions-list": ["exceptions", "list", str(exceptions)],
        "exceptions-validate": ["exceptions", "validate", str(next(exceptions.glob("*.yaml")))],
        "doctor": ["doctor"],
        "plugins": ["plugins"],
    }[command]
    result = _run("--json-logs", *args)
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines, "silent success gives an automation no result"
    events = [json.loads(line) for line in lines]
    assert all(isinstance(event.get("event"), str) for event in events)
    assert result.stderr == ""


@pytest.mark.parametrize(
    "command", ["verify", "guac", "statement", "vex", "enrich", "sarif", "oscal", "compare"]
)
@pytest.mark.parametrize("json_logs", [False, True])
def test_schema_failure_has_a_compact_error_on_the_right_stream(
    command: str, json_logs: bool, tmp_path: Path
) -> None:
    source = tmp_path / "empty.json"
    source.write_text("{}", encoding="utf-8")
    if command == "oscal":
        args = ["oscal", "--kind", "assessment-results", "--bundle", str(source)]
    elif command == "compare":
        args = ["compare", str(source), str(source)]
    else:
        args = [command, str(source)]
    result = _run(*(["--json-logs"] if json_logs else []), *args)
    assert result.returncode == 3
    combined = result.stdout + result.stderr
    assert "errors.pydantic.dev" not in combined
    assert "Traceback" not in combined
    if json_logs:
        assert result.stderr == ""
        events = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(events) == 1
        assert "schema" in events[0]["reason"].lower()
    else:
        assert result.stdout == ""
        assert len(result.stderr.splitlines()) == 1
        assert "schema" in result.stderr.lower()


def test_json_logs_keep_bad_options_machine_readable() -> None:
    result = _run("--json-logs", "compare", "x.json", "y.json", "--format", "jsno")
    assert result.returncode == 3
    assert result.stderr == ""
    event = json.loads(result.stdout)
    assert event["event"] == "command_failed"
    assert "--format" in event["reason"]


@pytest.mark.parametrize("json_logs", [False, True])
def test_evaluate_surfaces_foreign_release_evidence_in_its_result(
    bundle_file: Path, tmp_path: Path, json_logs: bool
) -> None:
    evidence = json.loads(bundle_file.read_text(encoding="utf-8"))["evidence"]
    evidence[0]["release_id"] = "other-release"
    source = tmp_path / "foreign.json"
    source.write_text(json.dumps({"evidence": evidence}), encoding="utf-8")
    args = [
        "evaluate",
        "--application",
        "example",
        "--repository",
        "acme/example",
        "--release-id",
        "1",
        "--commit-sha",
        "abcdef1234567890",
        "--fail-on",
        "conditional",
        "--evidence",
        str(source),
        "--output-dir",
        str(tmp_path / "foreign-bundle"),
    ]
    result = _run(*(["--json-logs"] if json_logs else []), *args)
    assert result.returncode == 1
    if json_logs:
        events = [json.loads(line) for line in result.stdout.splitlines()]
        errors = [event for event in events if event["event"] == "collection_error"]
        assert len(errors) == 1
        assert "other-release" in errors[0]["reason"]
        built = next(event for event in events if event["event"] == "bundle_built")
        assert built["collection_error_count"] == 1
    else:
        assert "other-release" in result.stdout
        assert "Collection warnings" in result.stdout
