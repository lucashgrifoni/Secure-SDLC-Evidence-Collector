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
from typing import Any

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


@pytest.mark.parametrize(
    ("input_name", "flag"),
    [
        ("exceptions-dir", "--exceptions-dir"),
        ("artifact-root", "--artifact-root"),
        ("profile", "--profile"),
        ("risk-mode", "--risk-mode"),
        ("epss-percentile-threshold", "--epss-percentile-threshold"),
        ("catalog", "--catalog"),
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


def test_summary_outputs_are_wired_to_the_collect_step(action: dict[str, Any]) -> None:
    wiring = {name: action["outputs"][name]["value"] for name in _SUMMARY_OUTPUTS}
    assert wiring == {
        name: "${{ steps.collect.outputs." + name + " }}" for name in _SUMMARY_OUTPUTS
    }


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

    assert set(outputs) == _PUBLISHED_OUTPUTS | _SUMMARY_OUTPUTS
    assert outputs["release-status"] == "ready"
    assert outputs["controls-total"] == "13"
    assert outputs["controls-met"] == "13"
    assert outputs["controls-missing"] == "0"
    assert Path(outputs["report-path"]).name == "report.md"
    assert Path(outputs["report-path"]).is_file()
    text = summary_file.read_text(encoding="utf-8")
    assert "| `ready` | 100 | 13 | 0 | 0 | 0 | 13 |" in text
    assert "Missing critical evidence: none" in text


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
