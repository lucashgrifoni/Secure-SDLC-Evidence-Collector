"""Execute the shipped component shell and its consumer assertions locally."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPONENT = ROOT / "examples/gitlab-component"


def _bash() -> str:
    candidates = [Path(r"C:\Program Files\Git\bin\bash.exe"), Path("/usr/bin/bash")]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.skip("Git Bash or POSIX Bash is needed for the component shell contract")


def _template() -> dict[str, Any]:
    documents = list(
        yaml.safe_load_all((COMPONENT / "templates/collect.yml").read_text(encoding="utf-8"))
    )
    return cast(dict[str, Any], documents[1]["$[[ inputs.job-name ]]"])


def _env(tmp_path: Path) -> dict[str, str]:
    return dict(os.environ) | {
        "PATH": str(Path(shutil.which("sdlc-evidence") or "").parent)
        + os.pathsep
        + os.environ["PATH"],
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
        "CI_PROJECT_DIR": str(tmp_path),
    }


def _run(script: str, tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_bash(), "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=35
    )


def test_component_and_consumer_pipeline(tmp_path: Path) -> None:
    env = _env(tmp_path)
    ci = yaml.safe_load((COMPONENT / ".gitlab-ci.yml").read_text(encoding="utf-8"))
    for script in (
        ci["prepare-fixtures"]["script"] + _template()["script"] + ci["verify-bundle"]["script"]
    ):
        result = _run(script, tmp_path, env)
        assert result.returncode == 0, result.stdout + result.stderr


def test_inputs_remain_literal_quoted_arguments(tmp_path: Path) -> None:
    env = _env(tmp_path) | {"EVIDENCE_APPLICATION": "$(touch INJECTED) ; $HOME ** [x]"}
    spy = (
        "sdlc-evidence() { python -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \"$@\"; }\n"
    )
    result = _run(spy + _template()["script"][0], tmp_path, env)
    assert result.returncode == 0, result.stderr
    argv = json.loads(result.stdout)
    assert argv[argv.index("--application") + 1] == env["EVIDENCE_APPLICATION"]
    assert argv[argv.index("--artifacts-dir") + 1] == "scanner output"
    assert not (tmp_path / "INJECTED").exists()
