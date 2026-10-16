"""`action.yml` is the primary consumption surface — pin its contract.

The reusable GitHub Action is what the README recommends for running the
collector in a pipeline, but it exposed only a subset of `run`'s flags. Waivers
in particular are sold as a differentiator in the README while
`--exceptions-dir` had no input at all, so an approved, time-bound exception
could not reach a bundle produced in CI. `--artifact-root` was missing too,
which is why Action-produced bundles recorded the runner's absolute paths.

Two things are pinned here:

* every `run` flag a caller could reasonably need has an input, and the input
  is actually forwarded to the command (declaring it is not enough); and
* the three published outputs keep their names — renaming `release-status`
  would silently break every workflow that reads it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, NamedTuple

import pytest
import yaml

_ACTION = Path("action.yml")

# Inputs a pipeline needs to reach parity with the `run` command.
_REQUIRED_INPUTS = {
    "application",
    "repository",
    "release-id",
    "commit-sha",
    "artifacts-dir",
    "attestations-dir",
    "exceptions-dir",
    "artifact-root",
    "catalog",
    "profile",
    "risk-mode",
    "epss-percentile-threshold",
    "fail-on",
    "output-dir",
    "cra-context",
    "fedramp-class",
}

# Renaming any of these is a breaking change for consumers.
_PUBLISHED_OUTPUTS = {"bundle-path", "release-status", "coverage-score"}


@pytest.fixture(scope="module")
def action() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(_ACTION.read_text(encoding="utf-8"))
    return data


@pytest.fixture(scope="module")
def collect_step(action: dict[str, Any]) -> dict[str, Any]:
    steps = action["runs"]["steps"]
    step: dict[str, Any] = next(s for s in steps if s.get("id") == "collect")
    return step


def test_every_required_input_is_declared(action: dict[str, Any]) -> None:
    missing = _REQUIRED_INPUTS - set(action["inputs"])
    assert not missing, f"action.yml does not expose: {sorted(missing)}"


def test_published_outputs_keep_their_names(action: dict[str, Any]) -> None:
    assert set(action["outputs"]) >= _PUBLISHED_OUTPUTS


def test_description_fits_the_marketplace_limit(action: dict[str, Any]) -> None:
    # The Marketplace refuses to list an Action whose description is 125
    # characters or longer, and it checks the action.yml at the release tag.
    assert len(action["description"]) < 125


@pytest.mark.parametrize(
    ("input_name", "flag"),
    [
        ("exceptions-dir", "--exceptions-dir"),
        ("artifact-root", "--artifact-root"),
        ("profile", "--profile"),
        ("risk-mode", "--risk-mode"),
        ("epss-percentile-threshold", "--epss-percentile-threshold"),
        ("catalog", "--catalog"),
        ("cra-context", "--cra-context"),
        ("fedramp-class", "--fedramp-class"),
    ],
)
def test_input_is_forwarded_to_the_command(
    collect_step: dict[str, Any], input_name: str, flag: str
) -> None:
    """Declaring an input without passing it is the bug this guards against."""
    env = collect_step["env"]
    env_var = input_name.upper().replace("-", "_")
    assert env_var in env, f"{input_name} is not wired into the step env"
    assert f"inputs.{input_name}" in env[env_var]
    assert flag in collect_step["run"], f"{flag} is never added to the run command"


@pytest.mark.parametrize(
    "path",
    [
        Path(".github/workflows/reusable-evidence-collection.yml"),
        Path("examples/gitlab-ci/secure-sdlc-evidence.yml"),
    ],
)
def test_ci_templates_can_pass_cra_context_and_fedramp_class(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for flag in ("--cra-context", "--fedramp-class", "catalog-fedramp-cr26.yaml"):
        assert flag in text, f"{path} does not mention {flag}"


def test_new_profile_inputs_default_to_unset(action: dict[str, Any]) -> None:
    for name in ("cra-context", "fedramp-class"):
        assert action["inputs"][name].get("default", "") == ""
        assert action["inputs"][name].get("required") is False


def test_exceptions_dir_is_not_silently_skipped(collect_step: dict[str, Any]) -> None:
    """A configured-but-missing waiver directory must not be quietly dropped.

    The optional evidence directories are guarded with `[ -d ... ]`, which
    skips them when absent. Waivers are different: losing an approved exception
    without a word changes the verdict, so the value is passed through and the
    collector reports the bad path.
    """
    run = collect_step["run"]
    assert '[ -n "$EXCEPTIONS_DIR" ]' in run
    assert '[ -d "$EXCEPTIONS_DIR" ]' not in run


def test_artifact_root_defaults_to_the_workspace(action: dict[str, Any]) -> None:
    """Otherwise bundles built by the Action leak the runner's absolute paths."""
    assert "github.workspace" in str(action["inputs"]["artifact-root"]["default"])


def test_every_public_cli_option_has_help_text() -> None:
    """`--help` is cited as the interface documentation, so it must be complete.

    25 of 69 public options shipped with no help at all, including every
    optional flag on `bundle` and most of `evaluate`. That contradicts
    docs/program/openssf-bestpractices-answers.md, which claims the
    documentation_interface criterion is met by "README.md + `--help`".
    """
    from typer.main import get_command

    from evidence_collector.cli.main import app as cli_app

    missing: list[str] = []
    visited: list[str] = []

    # Duck-typed rather than `isinstance(..., click.Group)`. Typer 0.27 dropped
    # its click dependency and vendors its own copy as `typer._click`, so the
    # objects here are not instances of the real click classes even when click
    # happens to be installed. The isinstance version therefore treated the root
    # group as a leaf and this test passed while checking a single command's
    # options — the guard reporting success without doing its job. `visited`
    # below is what makes that failure visible instead of silent.
    def walk(command: Any, prefix: str = "") -> None:
        subcommands = getattr(command, "commands", None)
        if subcommands:
            for name, sub in subcommands.items():
                walk(sub, f"{prefix}{name} ")
            return
        visited.append(prefix.strip() or "(root)")
        for param in command.params:
            if getattr(param, "param_type_name", "") != "option":
                continue
            if not param.help and not param.hidden:
                missing.append(f"{prefix.strip() or '(root)'} {'/'.join(param.opts)}")

    walk(get_command(cli_app))
    assert len(visited) > 10, f"the walk only reached {visited} — it is not checking the CLI"
    assert missing == [], f"options without help: {missing}"


# Outputs added with the job summary. They extend the three above; nothing
# published before them changes.
_SUMMARY_OUTPUTS = {
    "report-path",
    "controls-total",
    "controls-met",
    "controls-partial",
    "controls-missing",
}


# Outputs that let a later step reconcile the totals (the five control counts
# add up to controls-total) and see whether any input could not be read.
_TOTALS_OUTPUTS = {"controls-waived", "controls-not-applicable", "collection-errors"}


@pytest.mark.parametrize("outputs", [_SUMMARY_OUTPUTS, _TOTALS_OUTPUTS])
def test_summary_outputs_are_wired_to_the_collect_step(
    action: dict[str, Any], outputs: set[str]
) -> None:
    wiring = {name: action["outputs"][name]["value"] for name in outputs}
    assert wiring == {name: "${{ steps.collect.outputs." + name + " }}" for name in outputs}


def _output_script(collect_step: dict[str, Any]) -> str:
    import re

    match = re.search(r"<<'PY'[^\n]*\n(.*?)\nPY\n", collect_step["run"], re.DOTALL)
    assert match is not None, "the collect step no longer embeds its output script"
    return match.group(1)


def _run_output_script(
    collect_step: dict[str, Any], bundle: Path, summary_file: Path
) -> dict[str, str]:
    import os
    import subprocess
    import sys

    env = dict(os.environ, BUNDLE_FILE=str(bundle), GITHUB_STEP_SUMMARY=str(summary_file))
    completed = subprocess.run(
        [sys.executable, "-c", _output_script(collect_step)],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)


@pytest.fixture(scope="module")
def sample_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    from evidence_collector.application.orchestrator import run_pipeline
    from evidence_collector.domain.models import Application, ReleaseContext

    out = tmp_path_factory.mktemp("action-bundle")
    result = run_pipeline(
        Application(name="payments-api", repository="acme/payments-api"),
        ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890", branch="main"),
        artifacts_dirs=[Path("examples/sample_release/artifacts")],
        attestations_dirs=[Path("examples/sample_release/attestations")],
        output_dir=out,
    )
    assert result.json_path is not None
    return result.json_path


def test_the_output_script_reports_every_output_and_writes_a_summary(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    summary_file = tmp_path / "summary.md"
    outputs = _run_output_script(collect_step, sample_bundle, summary_file)

    assert set(outputs) == _PUBLISHED_OUTPUTS | _SUMMARY_OUTPUTS | _TOTALS_OUTPUTS
    assert outputs["release-status"] == "ready"
    assert outputs["controls-total"] == "13"
    assert outputs["controls-met"] == "13"
    assert outputs["controls-missing"] == "0"
    assert outputs["controls-waived"] == "0"
    assert outputs["controls-not-applicable"] == "0"
    assert outputs["collection-errors"] == "0"
    assert Path(outputs["report-path"]).name == "report.md"
    assert Path(outputs["report-path"]).is_file()
    text = summary_file.read_text(encoding="utf-8")
    assert "| `ready` | 100 | 13 | 0 | 0 | 0 | 0 | 13 |" in text
    assert "Missing critical evidence (not_ready): none" in text
    assert "Missing high evidence (conditional): none" in text
    assert "Collection warnings" not in text
    assert "Full report: `" in text and "report.md`" in text


def test_caller_text_in_the_summary_cannot_break_out_of_its_code_span(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    """Application name and release id come from workflow inputs.

    Rendered raw, a backtick closes the code span and a newline starts a new
    Markdown line, so a crafted value could add a heading, a link or an image
    to the job summary page.
    """
    import json

    data = json.loads(sample_bundle.read_text(encoding="utf-8"))
    data["application"]["name"] = "app`\n# Injected heading\n![x](https://example.invalid/x.png)"
    crafted = tmp_path / "bundle.json"
    crafted.write_text(json.dumps(data), encoding="utf-8")
    summary_file = tmp_path / "summary.md"

    _run_output_script(collect_step, crafted, summary_file)

    lines = summary_file.read_text(encoding="utf-8").splitlines()
    assert not any(line.startswith("# Injected") for line in lines)
    assert not any(line.startswith("![") for line in lines)
    assert lines[2].startswith(
        "`app' # Injected heading ![x](https://example.invalid/x.png)` release"
    )


_STEP_ENV = [
    "GITHUB_TOKEN",
    "APPLICATION",
    "REPOSITORY",
    "RELEASE_ID",
    "COMMIT_SHA",
    "BRANCH",
    "TAG",
    "PIPELINE_RUN_ID",
    "BUILD_ID",
    "ENVIRONMENT",
    "FAIL_ON",
    "PULL_REQUEST",
    "WORKFLOW_RUN",
    "CATALOG",
    "ARTIFACTS_DIR",
    "ATTESTATIONS_DIR",
    "EXCEPTIONS_DIR",
    "ARTIFACT_ROOT",
    "PROFILE",
    "CRA_CONTEXT",
    "FEDRAMP_CLASS",
    "RISK_MODE",
    "EPSS_PERCENTILE_THRESHOLD",
]


class _StepRun(NamedTuple):
    code: int
    outputs: str
    summary: Path
    stdout: str
    cli_args: list[str]


def _bash_or_skip() -> str:
    import shutil

    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("the step is a bash script and this machine has no bash")
    return bash


def _run_collect_step(
    collect_step: dict[str, Any],
    tmp_path: Path,
    *,
    cli: str,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> _StepRun:
    """Run the step's shell script with `python [-P] -m ...` replaced by `cli`.

    Every other `python` call (the output script) goes to the real
    interpreter with its own flags, so what is under test is the step's own
    logic around the CLI. `cli` sees the arguments after the module name, and
    they are also recorded for the test.
    """
    import os
    import stat
    import subprocess
    import sys

    bash = _bash_or_skip()
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "python"
    real = Path(sys.executable).as_posix()
    recorded = tmp_path / "cli_args.txt"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        'all=("$@")\n'
        'if [ "${1:-}" = "-P" ]; then shift; fi\n'
        'if [ "${1:-}" = "-m" ]; then\n'
        "shift 2\n"
        f'printf "%s\\n" "$@" > "{recorded.as_posix()}"\n'
        f"{cli}\n"
        "fi\n"
        f'exec "{real}" "${{all[@]}}"\n',
        encoding="utf-8",
        newline="\n",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    outputs = tmp_path / "github_output"
    outputs.write_text("", encoding="utf-8")
    summary = tmp_path / "step_summary.md"
    step_env = dict(os.environ)
    step_env.update(dict.fromkeys(_STEP_ENV, ""))
    step_env.update(
        PATH=f"{shim_dir}{os.pathsep}{step_env['PATH']}",
        OUTPUT_DIR=str(tmp_path / "out"),
        GITHUB_OUTPUT=str(outputs),
        GITHUB_STEP_SUMMARY=str(summary),
        FAIL_ON="not_ready",
    )
    step_env.update(env or {})
    completed = subprocess.run(
        [bash, "-c", collect_step["run"]],
        env=step_env,
        capture_output=True,
        text=True,
        cwd=cwd,
    )
    cli_args = recorded.read_text(encoding="utf-8").splitlines() if recorded.exists() else []
    return _StepRun(
        completed.returncode,
        outputs.read_text(encoding="utf-8"),
        summary,
        completed.stdout,
        cli_args,
    )


def _not_ready_copy(sample_bundle: Path, tmp_path: Path) -> Path:
    import json

    data = json.loads(sample_bundle.read_text(encoding="utf-8"))
    data["summary"]["release_status"] = "not_ready"
    fresh = tmp_path / "not_ready.json"
    fresh.write_text(json.dumps(data), encoding="utf-8")
    return fresh


def _writes_bundle_then_exits(bundle: Path, code: int) -> str:
    return (
        f'mkdir -p "$OUTPUT_DIR"; sleep 0.1; cp "{bundle.as_posix()}" '
        f'"$OUTPUT_DIR/bundle.json"; exit {code}'
    )


def test_a_bundle_left_by_an_earlier_run_is_not_reported(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    """The CLI can fail before writing anything (bad catalog, bad profile).

    A bundle already sitting in the output directory, from an earlier step or
    a reused self-hosted runner, must not be reported as this run's verdict.
    """
    out = tmp_path / "out"
    out.mkdir()
    (out / "bundle.json").write_bytes(sample_bundle.read_bytes())

    run = _run_collect_step(collect_step, tmp_path, cli="exit 3")

    assert run.code == 3
    assert "release-status=" not in run.outputs
    assert not run.summary.exists()


def test_a_bundle_written_by_a_failing_run_is_still_reported(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    """`--fail-on` exits nonzero after writing the bundle; that verdict counts."""
    out = tmp_path / "out"
    out.mkdir()
    (out / "bundle.json").write_bytes(sample_bundle.read_bytes())
    fresh = tmp_path / "fresh.json"
    fresh.write_bytes(sample_bundle.read_bytes())

    run = _run_collect_step(collect_step, tmp_path, cli=_writes_bundle_then_exits(fresh, 2))

    assert run.code == 2
    assert "release-status=ready" in run.outputs
    assert run.summary.is_file()


# --- python -P (SEC-06) -----------------------------------------------------


def _run_scripts(path: Path) -> list[str]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if "runs" in document:
        steps = document["runs"]["steps"]
    else:
        steps = [step for job in document["jobs"].values() for step in job.get("steps", [])]
    return [step["run"] for step in steps if "run" in step]


@pytest.mark.parametrize(
    "path", [_ACTION, Path(".github/workflows/reusable-evidence-collection.yml")]
)
def test_every_python_call_keeps_the_working_directory_off_sys_path(path: Path) -> None:
    """The working directory is the caller's checkout, which may be untrusted.

    `python -m`, `python -c` and `python -` put it first on sys.path, so a
    json.py or typer.py committed there runs inside the step, with the job
    token in the environment, and can write the step outputs.
    """
    import re

    calls = [
        match.group(0)
        for script in _run_scripts(path)
        for line in script.splitlines()
        if not line.lstrip().startswith("#")
        for match in re.finditer(r"\bpython3?\s+-\S*", line)
    ]
    assert calls, f"{path} runs no python; the check would pass vacuously"
    unsafe = [call for call in calls if not call.endswith(" -P")]
    assert not unsafe, f"{path}: python calls without -P: {unsafe}"


def test_a_module_planted_in_the_workspace_cannot_forge_the_outputs(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    """A planted json.py used to be imported by the output script."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = tmp_path / "planted-module-ran"
    (workspace / "json.py").write_text(
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('imported')\n"
        "print('release-status=ready')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    fresh = _not_ready_copy(sample_bundle, tmp_path)

    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli=_writes_bundle_then_exits(fresh, 2),
        cwd=workspace,
    )

    assert not marker.exists(), "the planted json.py was imported"
    assert "release-status=not_ready" in run.outputs
    assert "release-status=ready" not in run.outputs
    assert run.code == 2


# --- GITHUB_TOKEN scope (SEC-06, PIP-12) ------------------------------------


def test_the_token_reaches_the_collector_only_for_github_api_inputs(
    collect_step: dict[str, Any],
) -> None:
    """Only --pull-request and --workflow-run read GITHUB_TOKEN."""
    token = collect_step["env"]["GITHUB_TOKEN"]
    assert token != "${{ github.token }}"
    assert "inputs.pull-request != ''" in token
    assert "inputs.workflow-run != ''" in token
    assert token.replace(" ", "").endswith("&&github.token||''}}")


# --- observe mode (ADO-02) --------------------------------------------------


def test_observe_mode_reports_a_not_ready_verdict_without_failing(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    fresh = _not_ready_copy(sample_bundle, tmp_path)

    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli=_writes_bundle_then_exits(fresh, 2),
        env={"FAIL_ON": "none"},
    )

    assert run.code == 0
    assert "release-status=not_ready" in run.outputs
    # The CLI has no `none`; the step passes its default threshold.
    assert run.cli_args[run.cli_args.index("--fail-on") + 1] == "not_ready"
    assert "::notice title=Observe mode::" in run.stdout


def test_observe_mode_still_fails_when_the_collector_cannot_run(
    collect_step: dict[str, Any], tmp_path: Path
) -> None:
    run = _run_collect_step(collect_step, tmp_path, cli="exit 3", env={"FAIL_ON": "NONE"})

    assert run.code == 3
    assert "release-status=" not in run.outputs


def test_the_other_fail_on_values_reach_the_collector_unchanged(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    fresh = _not_ready_copy(sample_bundle, tmp_path)

    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli=_writes_bundle_then_exits(fresh, 2),
        env={"FAIL_ON": "conditional"},
    )

    assert run.code == 2
    assert run.cli_args[run.cli_args.index("--fail-on") + 1] == "conditional"


# --- missing evidence directories (ADO-09, CON-10) --------------------------


def test_a_missing_evidence_directory_is_named_in_the_log(
    collect_step: dict[str, Any], tmp_path: Path
) -> None:
    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli="exit 3",
        env={"ARTIFACTS_DIR": "scan-otput", "ATTESTATIONS_DIR": "attestations"},
        cwd=tmp_path,
    )

    lines = run.stdout.splitlines()
    assert (
        "::warning title=artifacts-dir not found::artifacts-dir 'scan-otput' does not exist, "
        "so nothing was collected from it." in lines
    )
    # The default value gets a notice: the quick start never creates it.
    assert (
        "::notice title=attestations-dir not found::attestations-dir 'attestations' does not "
        "exist, so nothing was collected from it." in lines
    )
    assert "--artifacts-dir" not in run.cli_args
    assert "--attestations-dir" not in run.cli_args


def test_a_directory_name_cannot_start_a_workflow_command(
    collect_step: dict[str, Any], tmp_path: Path
) -> None:
    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli="exit 3",
        env={"ARTIFACTS_DIR": "x\n::add-mask::secret %0A", "ATTESTATIONS_DIR": ""},
        cwd=tmp_path,
    )

    assert not any(line.startswith("::add-mask::") for line in run.stdout.splitlines())
    assert "x%0A::add-mask::secret %250A" in run.stdout


def test_collection_errors_and_the_gap_split_reach_the_summary(
    collect_step: dict[str, Any], sample_bundle: Path, tmp_path: Path
) -> None:
    import json

    data = json.loads(sample_bundle.read_text(encoding="utf-8"))
    data["summary"]["missing_critical_evidence"] = [
        "ORG-CODE-REVIEW:code_review",
        "SSDF-PW.7:sast_scan",
    ]
    data["collection_errors"] = [
        {"path": f"artifacts/broken-{n}.sarif", "reason": "not valid JSON"} for n in range(12)
    ]
    crafted = tmp_path / "bundle.json"
    crafted.write_text(json.dumps(data), encoding="utf-8")
    summary_file = tmp_path / "summary.md"

    outputs = _run_output_script(collect_step, crafted, summary_file)

    assert outputs["collection-errors"] == "12"
    text = summary_file.read_text(encoding="utf-8")
    assert "Missing critical evidence (not_ready): `ORG-CODE-REVIEW:code_review`" in text
    assert "Missing high evidence (conditional): `SSDF-PW.7:sast_scan`" in text
    assert "Collection warnings, inputs that could not be read (12):" in text
    assert "- `artifacts/broken-0.sarif`: `not valid JSON`" in text
    assert "- `artifacts/broken-10.sarif`" not in text
    assert "- 2 more in the report" in text


# --- release lineage (ADO-10, CON-05) ---------------------------------------


def test_lineage_inputs_default_to_the_github_run(action: dict[str, Any]) -> None:
    inputs = action["inputs"]
    assert inputs["tag"]["default"] == "${{ github.ref_type == 'tag' && github.ref_name || '' }}"
    assert inputs["pipeline-run-id"]["default"] == "${{ github.run_id }}"
    assert inputs["build-id"]["default"] == "${{ github.run_id }}-${{ github.run_attempt }}"
    branch = inputs["branch"]["default"]
    # A tag is not a branch, and `<number>/merge` is not one either.
    assert branch.startswith("${{ github.head_ref ||")
    assert "github.ref_type == 'branch' && github.ref_name" in branch
    assert "github.event.repository.default_branch" in branch


def test_lineage_reaches_the_command(collect_step: dict[str, Any], tmp_path: Path) -> None:
    run = _run_collect_step(
        collect_step,
        tmp_path,
        cli="exit 3",
        env={
            "BRANCH": "main",
            "TAG": "v1.2.3",
            "PIPELINE_RUN_ID": "4242",
            "BUILD_ID": "4242-2",
        },
    )

    args = run.cli_args
    assert args[args.index("--branch") + 1] == "main"
    assert args[args.index("--tag") + 1] == "v1.2.3"
    assert args[args.index("--pipeline-run-id") + 1] == "4242"
    assert args[args.index("--build-id") + 1] == "4242-2"


def test_empty_lineage_inputs_are_left_out(collect_step: dict[str, Any], tmp_path: Path) -> None:
    run = _run_collect_step(collect_step, tmp_path, cli="exit 3", env={"BRANCH": "main"})

    for flag in ("--tag", "--pipeline-run-id", "--build-id"):
        assert flag not in run.cli_args


# --- installation (PIP-12, INS-12, CON-06) ----------------------------------


def _run_install_step(
    action: dict[str, Any], tmp_path: Path, *, version: str, locked_python: bool
) -> tuple[str, list[list[str]]]:
    """Run the install step with a `python` that only records its calls."""
    import os
    import stat
    import subprocess

    bash = _bash_or_skip()
    step = next(s for s in action["runs"]["steps"] if s.get("name") == "Install collector")
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    log = tmp_path / "calls.txt"
    shim = shim_dir / "python"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        f'printf \'%s\\037\' "$@" >> "{log.as_posix()}"\n'
        f"printf '\\n' >> \"{log.as_posix()}\"\n"
        'if [ "${2:-}" = "-c" ]; then\n'
        f"exit {0 if locked_python else 1}\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
        newline="\n",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ)
    env.update(
        PATH=f"{shim_dir}{os.pathsep}{env['PATH']}",
        VERSION=version,
        ACTION_PATH=Path.cwd().as_posix(),
    )
    completed = subprocess.run(
        [bash, "-c", step["run"]], env=env, capture_output=True, text=True, check=True
    )
    calls = [line.split("\x1f")[:-1] for line in log.read_text(encoding="utf-8").splitlines()]
    return completed.stdout, calls


def test_the_action_installs_dependencies_from_its_hash_locks(
    action: dict[str, Any], tmp_path: Path
) -> None:
    stdout, calls = _run_install_step(action, tmp_path, version="", locked_python=True)

    root = Path.cwd().as_posix()
    locks = f"{root}/.github/requirements"
    assert [call[:2] for call in calls] == [["-P", "-c"]] + [["-P", "-m"]] * 3
    assert calls[1][2:] == ["pip", "install", "--require-hashes", "-r", f"{locks}/pip.txt"]
    assert calls[2][2:] == ["pip", "install", "--require-hashes", "-r", f"{locks}/runtime.txt"]
    assert calls[3][2:] == ["pip", "install", "--no-deps", root]
    assert "::notice" not in stdout
    assert Path(".github/requirements/pip.txt").is_file()
    assert Path(".github/requirements/runtime.txt").is_file()


def test_other_python_versions_fall_back_to_the_ranges_with_a_notice(
    action: dict[str, Any], tmp_path: Path
) -> None:
    stdout, calls = _run_install_step(action, tmp_path, version="", locked_python=False)

    assert calls[-1] == ["-P", "-m", "pip", "install", Path.cwd().as_posix()]
    assert not any("--require-hashes" in call for call in calls)
    assert "::notice title=Dependencies not hash-locked::" in stdout


@pytest.mark.parametrize(
    ("version", "ref"),
    [("4.2.0", "v4.2.0"), ("v4.2.0", "v4.2.0"), ("main", "main"), ("4.2", "4.2")],
)
def test_a_release_number_is_read_as_its_tag(
    action: dict[str, Any], tmp_path: Path, version: str, ref: str
) -> None:
    """The reusable workflow and the component take `4.2.0`; the tag is `v4.2.0`."""
    _, calls = _run_install_step(action, tmp_path, version=version, locked_python=True)

    assert calls == [
        [
            "-P",
            "-m",
            "pip",
            "install",
            "--upgrade",
            f"git+https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector@{ref}",
        ]
    ]
