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


def _conflicting_vex(tmp_path: Path, bundle_file: Path) -> Path:
    """A consumed OpenVEX statement that disagrees with the bundle's own one."""
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    cve = next(cve for item in bundle["evidence"] for cve in item.get("cve_ids") or [])
    source = tmp_path / "vendor.openvex.json"
    source.write_text(
        json.dumps(
            {
                "@context": "https://openvex.dev/ns/v0.2.0",
                "statements": [
                    {
                        "vulnerability": {"name": cve},
                        "status": "not_affected",
                        "justification": "vulnerable_code_not_present",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return source


@pytest.mark.parametrize("command", ["statement", "enrich", "vex"])
@pytest.mark.parametrize("json_logs", [False, True])
def test_command_specific_failures_use_the_right_stream(
    command: str, json_logs: bool, bundle_file: Path, tmp_path: Path
) -> None:
    args = {
        "statement": ["statement", str(bundle_file), "--predicate-type", "bogus"],
        "enrich": ["enrich", str(bundle_file), "--epss-feed", str(tmp_path / "nofeed.csv")],
        "vex": [
            "vex",
            str(bundle_file),
            "--output",
            str(tmp_path / "openvex.json"),
            "--consume",
            str(_conflicting_vex(tmp_path, bundle_file)),
            "--policy",
            "fail",
        ],
    }[command]
    result = _run(*(["--json-logs"] if json_logs else []), *args)
    assert result.returncode == 3, result.stdout + result.stderr
    if json_logs:
        assert result.stderr == ""
        events = [json.loads(line) for line in result.stdout.splitlines()]
        assert len(events) == 1
        assert events[0]["event"] == f"{command}_failed"
    else:
        assert result.stdout == ""
        assert len(result.stderr.splitlines()) == 1


def test_verify_accepts_an_algorithm_prefixed_pin(bundle_file: Path) -> None:
    digest = structural_sha256(bundle_file)
    assert _run("verify", str(bundle_file), "--expected", f"sha256:{digest}").returncode == 0
    assert _run("verify", str(bundle_file), "--expected", f"SHA256:{digest}").returncode == 0
    assert _run("verify", str(bundle_file), "--expected", f"sha256:{'0' * 64}").returncode == 2
    assert _run("verify", str(bundle_file), "--expected", "sha256:").returncode == 3
    assert _run("verify", str(bundle_file), "--expected", f"md5:{digest}").returncode == 3


def test_verify_help_states_the_pin_format_and_exit_codes() -> None:
    help_text = " ".join(_run("verify", "--help").stdout.split())
    assert "sha256:" in help_text
    assert "64 hexadecimal" in help_text
    assert "exit" in help_text.lower() and "3" in help_text


def test_json_logs_version_is_an_event() -> None:
    result = _run("--json-logs", "--version")
    assert result.returncode == 0
    event = json.loads(result.stdout)
    assert event["event"] == "version"
    assert event["version"] == _run("--version").stdout.strip()


# Commands whose stdout is a document or data payload, and the event that
# carries it under --json-logs: (argv, event name, payload key).
_JSON_LOGS_PAYLOADS: dict[str, tuple[list[str], str, str]] = {
    "schema": (["schema"], "schema_emitted", "schema"),
    "oscal": (["oscal", "--kind", "catalog"], "oscal_emitted", "document"),
    "plugins": (["plugins"], "plugins_listed", "plugins"),
    "controls": (["controls"], "controls_listed", "controls"),
    "doctor": (["doctor", "--json"], "doctor_checked", "checks"),
    "compare": (["compare", "{bundle}", "{bundle}", "--format", "json"], "bundles_compared", ""),
    "verify": (["verify", "{bundle}"], "verify_computed", "sha256"),
    "exceptions": (["exceptions", "list", "{exceptions}"], "exception_listed", "exception"),
}


@pytest.mark.parametrize("command", sorted(_JSON_LOGS_PAYLOADS))
def test_json_logs_payload_shapes_are_pinned_and_documented(
    command: str, bundle_file: Path, sample_release_root: Path
) -> None:
    argv, event_name, key = _JSON_LOGS_PAYLOADS[command]
    argv = [
        arg.format(bundle=bundle_file, exceptions=sample_release_root / "exceptions")
        for arg in argv
    ]
    result = _run("--json-logs", *argv)
    assert result.returncode == 0, result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    event = next(item for item in events if item["event"] == event_name)
    if key:
        assert key in event
    doc = (
        Path(__file__).resolve().parents[2] / "docs" / "evidence-profile-migration.md"
    ).read_text(encoding="utf-8")
    assert f"`{event_name}`" in doc
    if key:
        assert f"`.{key}`" in doc


def test_documents_stay_raw_when_json_logs_are_off(bundle_file: Path) -> None:
    from evidence_collector.schema import bundle_json_schema_text

    assert _run("schema").stdout == bundle_json_schema_text()
    catalog = json.loads(_run("oscal", "--kind", "catalog").stdout)
    assert "event" not in catalog and "catalog" in catalog
    comparison = json.loads(
        _run("compare", str(bundle_file), str(bundle_file), "--format", "json").stdout
    )
    assert "event" not in comparison
    doctor = json.loads(_run("doctor", "--json").stdout)
    assert set(doctor) == {"checks", "failed"}


def test_exception_errors_name_the_file_once_and_do_not_echo_values(
    tmp_path: Path, sample_release_root: Path
) -> None:
    template = next((sample_release_root / "exceptions").glob("*.yaml")).read_text(encoding="utf-8")
    lines = [
        'expires_at: "SECRETDATE-ghp_xyz"' if line.startswith("expires_at:") else line
        for line in template.splitlines()
    ]
    bad = tmp_path / "bad_exc.yaml"
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for args in (["exceptions", "validate", str(bad)], ["exceptions", "list", str(tmp_path)]):
        result = _run(*args)
        assert "SECRETDATE" not in result.stdout + result.stderr
        assert len(result.stderr.splitlines()) == 1
        assert result.stderr.count("exception file") == 1
        assert "expires_at" in result.stderr


def test_attestation_errors_name_the_field_without_echoing_the_value(tmp_path: Path) -> None:
    from evidence_collector.parsers import parse_attestation
    from evidence_collector.parsers._common import ParseError

    base = {
        "evidence_type": "code_review",
        "producer": "p",
        "subject_type": "pull_request",
        "subject_ref": "PR-1",
    }
    for field, value in (
        ("confidence", "extremely-high-SECRETVALUE"),
        ("generated_at", "SECRETVALUE"),
    ):
        source = tmp_path / f"{field}.json"
        source.write_text(json.dumps({**base, field: value}), encoding="utf-8")
        with pytest.raises(ParseError) as caught:
            parse_attestation(source)
        assert field in str(caught.value)
        assert "SECRETVALUE" not in str(caught.value)
