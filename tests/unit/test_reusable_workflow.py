"""The reusable workflow keeps its bundle, its gate and its outputs.

It was the "one `uses:` line" path, and it failed its users in three ways at
once. The upload step had no condition, so a `not_ready` release, the one
whose report matters, uploaded nothing. `--fail-on not_ready` was hard-coded
and the workflow declared no outputs, so a caller could neither tighten the
gate nor read the verdict. And it runs on a fresh runner with no way to bring
scanner output from an earlier job, so the documented `artifacts-dir:
scanner-output` pointed at a directory that does not exist there.

The run step's script is executed here with a stand-in for `sdlc-evidence`,
the same way the Action's step is in test_action_contract.py.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml

_WORKFLOW = Path(".github/workflows/reusable-evidence-collection.yml")
_OUTPUTS = {
    "release-status",
    "coverage-score",
    "controls-total",
    "controls-met",
    "controls-partial",
    "controls-missing",
    "controls-waived",
    "controls-not-applicable",
    "collection-errors",
}


@pytest.fixture(scope="module")
def workflow() -> dict[Any, Any]:
    data: dict[Any, Any] = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    return data


@pytest.fixture(scope="module")
def call(workflow: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML reads the bare key `on` as the boolean True.
    trigger = workflow.get("on", workflow.get(True))
    assert isinstance(trigger, dict)
    spec: dict[str, Any] = trigger["workflow_call"]
    return spec


@pytest.fixture(scope="module")
def job(workflow: dict[Any, Any]) -> dict[str, Any]:
    collect: dict[str, Any] = workflow["jobs"]["collect"]
    return collect


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    step: dict[str, Any] = next(s for s in job["steps"] if s.get("name") == name)
    return step


def test_the_bundle_is_uploaded_when_the_run_fails(job: dict[str, Any]) -> None:
    upload = _step(job, "Upload bundle and report")
    assert upload.get("if") == "${{ !cancelled() }}"
    # A run that could not start wrote nothing and already failed the job.
    assert upload["with"]["if-no-files-found"] == "warn"


def test_fail_on_is_an_input_that_keeps_the_old_default(
    call: dict[str, Any], job: dict[str, Any]
) -> None:
    assert call["inputs"]["fail-on"]["default"] == "not_ready"
    run = _step(job, "Run sdlc-evidence")
    assert run["env"]["FAIL_ON"] == "${{ inputs.fail-on }}"
    assert "--fail-on not_ready" not in run["run"]


def test_the_environment_input_keeps_the_recorded_default(call: dict[str, Any]) -> None:
    """Every bundle said `production` before; that stays the default in 4.x."""
    assert call["inputs"]["environment"]["default"] == "production"


def test_every_output_is_wired_from_the_run_step(call: dict[str, Any], job: dict[str, Any]) -> None:
    assert set(call["outputs"]) == _OUTPUTS
    for name in _OUTPUTS:
        assert call["outputs"][name]["value"] == "${{ jobs.collect.outputs." + name + " }}"
        assert job["outputs"][name] == "${{ steps.run.outputs." + name + " }}"
    assert _step(job, "Run sdlc-evidence")["id"] == "run"


def test_scanner_output_from_an_earlier_job_is_downloaded_first(
    call: dict[str, Any], job: dict[str, Any]
) -> None:
    assert call["inputs"]["artifact-name"]["default"] == ""
    names = [step.get("name") for step in job["steps"]]
    download = _step(job, "Download scanner output")
    assert download["uses"].startswith("actions/download-artifact@")
    assert download["if"] == "${{ inputs.artifact-name != '' }}"
    assert download["with"] == {
        "name": "${{ inputs.artifact-name }}",
        "path": "${{ inputs.artifacts-dir }}",
    }
    assert names.index("Download scanner output") < names.index("Run sdlc-evidence")


def test_harden_runner_stays_on_by_default_and_can_be_turned_off(
    call: dict[str, Any], job: dict[str, Any]
) -> None:
    spec = call["inputs"]["harden-runner"]
    assert spec["type"] == "boolean"
    assert spec["default"] is True
    assert _step(job, "Harden runner")["if"] == "${{ inputs.harden-runner }}"


# --- install step (SEC-16) --------------------------------------------------


def _bash() -> str:
    import shutil

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("the step is a bash script and this machine has no bash")
    return bash


def _run_install(
    job: dict[str, Any], tmp_path: Path, env: dict[str, str]
) -> tuple[str, list[list[str]]]:
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    log = tmp_path / "calls.txt"
    shim = shim_dir / "python"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        f'printf \'%s\\037\' "$@" >> "{log.as_posix()}"\n'
        f"printf '\\n' >> \"{log.as_posix()}\"\n",
        encoding="utf-8",
        newline="\n",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    step_env = dict(os.environ, PATH=f"{shim_dir}{os.pathsep}{os.environ['PATH']}")
    step_env.update({"COLLECTOR_VERSION": "", "FROM_CHECKOUT": "false"} | env)
    completed = subprocess.run(
        [_bash(), "-c", _step(job, "Install secure-sdlc-evidence-collector")["run"]],
        env=step_env,
        capture_output=True,
        text=True,
        check=True,
    )
    calls = [line.split("\x1f")[:-1] for line in log.read_text(encoding="utf-8").splitlines()]
    return completed.stdout, calls


def test_an_unpinned_collector_is_announced(job: dict[str, Any], tmp_path: Path) -> None:
    stdout, calls = _run_install(job, tmp_path, {})

    assert "::notice title=Collector version not pinned::" in stdout
    assert calls == [["-P", "-m", "pip", "install", "secure-sdlc-evidence-collector"]]


def test_a_pinned_collector_is_installed_without_a_notice(
    job: dict[str, Any], tmp_path: Path
) -> None:
    stdout, calls = _run_install(job, tmp_path, {"COLLECTOR_VERSION": "4.2.0"})

    assert "::notice" not in stdout
    assert calls == [["-P", "-m", "pip", "install", "secure-sdlc-evidence-collector==4.2.0"]]


def test_the_self_test_installs_the_checkout_with_the_hash_locks(
    call: dict[str, Any], job: dict[str, Any], tmp_path: Path
) -> None:
    assert call["inputs"]["install-from-checkout"]["default"] is False
    _, calls = _run_install(job, tmp_path, {"FROM_CHECKOUT": "true"})

    assert calls == [
        ["-P", "-m", "pip", "install", "--require-hashes", "-r", ".github/requirements/pip.txt"],
        [
            "-P",
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            ".github/requirements/runtime.txt",
        ],
        ["-P", "-m", "pip", "install", "--no-deps", "."],
    ]


# --- run step ---------------------------------------------------------------


class _Run(NamedTuple):
    code: int
    outputs: dict[str, str]
    stdout: str
    cli_args: list[str]


_RUN_ENV = {
    "APPLICATION": "payments-api",
    "REPOSITORY": "acme/payments-api",
    "RELEASE_ID": "2026.04.10",
    "COMMIT_SHA": "abcdef1234567890",
    "BRANCH": "main",
    "TAG": "",
    "PIPELINE_RUN_ID": "",
    "BUILD_ID": "",
    "ENVIRONMENT": "production",
    "ARTIFACTS_DIR": "artifacts",
    "RISK_MODE": "off",
    "PROFILE": "none",
    "ATTESTATIONS_DIR": "",
    "EXCEPTIONS_DIR": "",
    "CATALOG_PATH": "",
    "CRA_CONTEXT": "",
    "FEDRAMP_CLASS": "",
    "FAIL_ON": "not_ready",
}


@pytest.fixture(scope="module")
def not_ready_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.domain.models import Application, ReleaseContext

    out = tmp_path_factory.mktemp("reusable-bundle")
    result = run_pipeline(
        Application(name="payments-api", repository="acme/payments-api"),
        ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main"),
        artifacts_dirs=[Path("examples/sample_release/artifacts")],
        output_dir=out,
    )
    assert result.json_path is not None
    data = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert data["summary"]["release_status"] == "not_ready"
    return result.json_path


def _run_step(job: dict[str, Any], tmp_path: Path, *, cli: str, env: dict[str, str]) -> _Run:
    """Run the step in a scratch workspace with `sdlc-evidence` replaced by `cli`."""
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    recorded = tmp_path / "cli_args.txt"
    (shim_dir / "sdlc-evidence").write_text(
        f'#!/usr/bin/env bash\nprintf "%s\\n" "$@" > "{recorded.as_posix()}"\n{cli}\n',
        encoding="utf-8",
        newline="\n",
    )
    (shim_dir / "python").write_text(
        f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    for shim in shim_dir.iterdir():
        shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    step_env = dict(os.environ, PATH=f"{shim_dir}{os.pathsep}{os.environ['PATH']}")
    step_env.update(_RUN_ENV | env | {"GITHUB_OUTPUT": str(outputs)})
    completed = subprocess.run(
        [_bash(), "-c", _step(job, "Run sdlc-evidence")["run"]],
        env=step_env,
        capture_output=True,
        text=True,
        cwd=workspace,
    )
    pairs = [line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines()]
    return _Run(
        completed.returncode,
        dict(pair for pair in pairs if len(pair) == 2),
        completed.stdout,
        recorded.read_text(encoding="utf-8").splitlines() if recorded.exists() else [],
    )


def _writes(bundle: Path, code: int) -> str:
    return (
        f'mkdir -p release-evidence; sleep 0.1; cp "{bundle.as_posix()}" '
        f"release-evidence/bundle.json; exit {code}"
    )


def test_a_not_ready_verdict_fails_the_job_and_still_sets_the_outputs(
    job: dict[str, Any], not_ready_bundle: Path, tmp_path: Path
) -> None:
    run = _run_step(job, tmp_path, cli=_writes(not_ready_bundle, 2), env={})

    assert run.code == 2
    assert run.outputs["release-status"] == "not_ready"
    assert run.outputs["controls-total"] == "13"
    assert run.outputs["collection-errors"] == "0"
    counts = ("met", "partial", "missing", "waived", "not-applicable")
    assert sum(int(run.outputs[f"controls-{name}"]) for name in counts) == 13
    assert run.cli_args[run.cli_args.index("--fail-on") + 1] == "not_ready"


def test_observe_mode_passes_a_not_ready_release(
    job: dict[str, Any], not_ready_bundle: Path, tmp_path: Path
) -> None:
    run = _run_step(job, tmp_path, cli=_writes(not_ready_bundle, 2), env={"FAIL_ON": "none"})

    assert run.code == 0
    assert run.outputs["release-status"] == "not_ready"
    assert run.cli_args[run.cli_args.index("--fail-on") + 1] == "not_ready"
    assert "::notice title=Observe mode::" in run.stdout


def test_observe_mode_still_fails_when_the_collector_cannot_run(
    job: dict[str, Any], tmp_path: Path
) -> None:
    run = _run_step(job, tmp_path, cli="exit 3", env={"FAIL_ON": "none"})

    assert run.code == 3
    assert run.outputs == {}


def test_a_stale_bundle_is_not_reported(
    job: dict[str, Any], not_ready_bundle: Path, tmp_path: Path
) -> None:
    stale = tmp_path / "workspace" / "release-evidence"
    stale.mkdir(parents=True)
    (stale / "bundle.json").write_bytes(not_ready_bundle.read_bytes())

    run = _run_step(job, tmp_path, cli="exit 3", env={})

    assert run.code == 3
    assert run.outputs == {}


def test_environment_and_lineage_reach_the_command(job: dict[str, Any], tmp_path: Path) -> None:
    run = _run_step(
        job,
        tmp_path,
        cli="exit 3",
        env={
            "ENVIRONMENT": "staging",
            "TAG": "v1.2.3",
            "PIPELINE_RUN_ID": "4242",
            "BUILD_ID": "4242-2",
        },
    )

    args = run.cli_args
    assert args[args.index("--environment") + 1] == "staging"
    assert args[args.index("--tag") + 1] == "v1.2.3"
    assert args[args.index("--pipeline-run-id") + 1] == "4242"
    assert args[args.index("--build-id") + 1] == "4242-2"


def test_empty_lineage_inputs_are_left_out(job: dict[str, Any], tmp_path: Path) -> None:
    run = _run_step(job, tmp_path, cli="exit 3", env={})

    for flag in ("--tag", "--pipeline-run-id", "--build-id"):
        assert flag not in run.cli_args


def test_a_package_planted_in_the_checkout_cannot_replace_the_catalog(
    job: dict[str, Any], tmp_path: Path
) -> None:
    """The catalog step imported `evidence_collector` from the working directory."""
    workspace = tmp_path / "workspace"
    planted = workspace / "evidence_collector" / "controls"
    planted.mkdir(parents=True)
    for package in (planted.parent, planted):
        (package / "__init__.py").write_text("", encoding="utf-8")
    (planted / "catalog.py").write_text(
        "def bundled_catalog_path(name):\n    return 'attacker-catalog.yaml'\n",
        encoding="utf-8",
    )
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "python"
    shim.write_text(
        f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    env = dict(os.environ, PATH=f"{shim_dir}{os.pathsep}{os.environ['PATH']}")
    env.update(CATALOG="catalog-ai.yaml", GITHUB_OUTPUT=str(outputs))
    env.pop("PYTHONPATH", None)

    subprocess.run(
        [_bash(), "-c", _step(job, "Resolve bundled catalog path (if requested)")["run"]],
        env=env,
        capture_output=True,
        text=True,
        cwd=workspace,
        check=True,
    )

    resolved = outputs.read_text(encoding="utf-8")
    assert "attacker-catalog.yaml" not in resolved
    assert Path(resolved.strip().split("=", 1)[1]).name == "catalog-ai.yaml"
