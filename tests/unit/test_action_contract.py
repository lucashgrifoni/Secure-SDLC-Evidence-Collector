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
