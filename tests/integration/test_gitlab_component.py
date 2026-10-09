"""Execute the shipped component shell and its consumer assertions locally."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "examples/gitlab-component"
_SHIM_DIR = ".cli-under-test"


def _bash() -> str:
    candidates = [Path(r"C:\Program Files\Git\bin\bash.exe"), Path("/usr/bin/bash")]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise pytest.skip.Exception("Git Bash or POSIX Bash is needed for the component shell contract")


def _template() -> dict[str, Any]:
    documents = list(
        yaml.safe_load_all((COMPONENT / "templates/collect.yml").read_text(encoding="utf-8"))
    )
    return cast(dict[str, Any], documents[1]["$[[ inputs.job-name ]]"])


def _cli_under_test(tmp_path: Path) -> Path:
    """Point ``sdlc-evidence`` at this checkout's source, whatever is installed."""
    shim_dir = tmp_path / _SHIM_DIR
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "sdlc-evidence"
    python = Path(sys.executable).as_posix()
    shim.write_text(
        f'#!/bin/sh\nexec "{python}" -m evidence_collector.cli.main "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    shim.chmod(0o755)
    return shim_dir


def _env(tmp_path: Path) -> dict[str, str]:
    # CI_* would leak the host pipeline into the shell under test. COV_CORE_*
    # makes pytest-cov 5 record the shell's Python processes from the temporary
    # working directory without the project's branch setting, and the parent
    # run then fails to combine statement data with branch data.
    inherited = {
        key: value for key, value in os.environ.items() if not key.startswith(("CI_", "COV_CORE_"))
    }
    return inherited | {
        "PATH": str(_cli_under_test(tmp_path)) + os.pathsep + os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "src"),
        "EVIDENCE_APPLICATION": "Demo release with spaces",
        "EVIDENCE_REPOSITORY": "demo/component",
        "EVIDENCE_RELEASE_ID": "test",
        "EVIDENCE_ARTIFACTS_DIR": "scanner output",
        "EVIDENCE_CATALOG": "tests/catalog.yaml",
        "EVIDENCE_ATTESTATIONS_DIR": "",
        "EVIDENCE_EXCEPTIONS_DIR": "",
        "EVIDENCE_FAIL_ON": "not_ready",
        "CI_COMMIT_SHA": "abcdef1234567890",
        "CI_COMMIT_REF_NAME": "main",
        "CI_COMMIT_BRANCH": "main",
        "CI_DEFAULT_BRANCH": "main",
        "CI_PIPELINE_ID": "4242",
        "CI_JOB_ID": "777",
        "CI_PROJECT_DIR": str(tmp_path),
    }


def _run(script: str, tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_bash(), "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=35
    )


_SPY = "sdlc-evidence() { python -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \"$@\"; }\n"


def _argv(tmp_path: Path, env: dict[str, str]) -> list[str]:
    result = _run(_SPY + _template()["script"][0], tmp_path, env)
    assert result.returncode == 0, result.stderr
    return cast(list[str], json.loads(result.stdout))


def _value(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv else None


def test_component_and_consumer_pipeline(tmp_path: Path) -> None:
    env = _env(tmp_path)
    ci = yaml.safe_load((COMPONENT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    for script in (
        ci["prepare-fixtures"]["script"] + _template()["script"] + ci["verify-bundle"]["script"]
    ):
        result = _run(script, tmp_path, env)
        assert result.returncode == 0, result.stdout + result.stderr


def test_shell_resolves_the_collector_under_test(tmp_path: Path) -> None:
    result = _run("command -v sdlc-evidence", tmp_path, _env(tmp_path))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith(f"{_SHIM_DIR}/sdlc-evidence"), result.stdout


def test_tag_pipeline_records_the_tag_not_a_branch(tmp_path: Path) -> None:
    env = _env(tmp_path) | {"CI_COMMIT_REF_NAME": "1.0.0", "CI_COMMIT_TAG": "1.0.0"}
    del env["CI_COMMIT_BRANCH"]
    argv = _argv(tmp_path, env)
    assert _value(argv, "--tag") == "1.0.0"
    assert _value(argv, "--branch") == "main"
    assert _value(argv, "--pipeline-run-id") == "4242"
    assert _value(argv, "--build-id") == "777"


def test_branch_pipeline_records_the_branch_and_no_tag(tmp_path: Path) -> None:
    env = _env(tmp_path) | {"CI_COMMIT_REF_NAME": "feature/x", "CI_COMMIT_BRANCH": "feature/x"}
    argv = _argv(tmp_path, env)
    assert _value(argv, "--branch") == "feature/x"
    assert "--tag" not in argv


def test_inputs_remain_literal_quoted_arguments(tmp_path: Path) -> None:
    env = _env(tmp_path) | {"EVIDENCE_APPLICATION": "$(touch INJECTED) ; $HOME ** [x]"}
    argv = _argv(tmp_path, env)
    assert _value(argv, "--application") == env["EVIDENCE_APPLICATION"]
    assert _value(argv, "--artifacts-dir") == "scanner output"
    assert not (tmp_path / "INJECTED").exists()
