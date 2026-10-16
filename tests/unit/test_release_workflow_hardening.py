"""Release-path rules that only a tag run would otherwise exercise.

`publish-pypi.yml` runs on a release tag, so a mistake in it is found by the
release it breaks, and a failed publish burns the version (3.0.0). These checks
hold the release path to rules a pull request can verify:

* every release job runs on a pinned runner image, and the Linux jobs of
  pull-request CI run on that same image. `ubuntu-latest` moves to Ubuntu
  26.04 from 2026-10-19 in a gradual rollout, so without a pin the first tag
  after it could be the first run on an image no pull request ran (PIP-01);
* a tag-triggered workflow restores no cache. The pip cache it used to restore
  was written by main-branch runs (PIP-11);
* values from the event or from other jobs reach a release `run:` script
  through the environment, never through the script text (PIP-14);
* a job asks for `attestations: write` only when it runs an attest action
  (PIP-15);
* the pull-request sample gate uses the same `--fail-on` as the publish job.
  Publish runs the sample with `--fail-on conditional`; CI used `not_ready`,
  so a change that dropped the sample to `conditional` passed CI and then
  failed the tag.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

WORKFLOW_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"
PUBLISH = WORKFLOW_DIR / "publish-pypi.yml"
PR_CI = (WORKFLOW_DIR / "github-ci-cd.yml", WORKFLOW_DIR / "security-ci-cd.yml")
_EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
_FAIL_ON = re.compile(r"--fail-on\s+(\S+)")


def _load(path: Path) -> dict[Any, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path.name} is not a mapping"
    return document


def _jobs(path: Path) -> dict[str, dict[str, Any]]:
    jobs = _load(path).get("jobs", {})
    return {name: job for name, job in jobs.items() if isinstance(job, dict)}


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [step for step in job.get("steps", []) if isinstance(step, dict)]


def _runner_labels(path: Path) -> dict[str, str]:
    """Map each job that picks its own runner to its `runs-on` label."""
    return {name: str(job["runs-on"]) for name, job in _jobs(path).items() if "runs-on" in job}


def _collector_runs(job: dict[str, Any]) -> list[str]:
    return [
        str(step["run"])
        for step in _steps(job)
        if "evidence_collector.cli.main run" in str(step.get("run", ""))
    ]


def test_release_jobs_run_on_one_pinned_image() -> None:
    labels = _runner_labels(PUBLISH)
    assert labels, "precondition: publish-pypi.yml has jobs with their own runner"
    floating = {name: label for name, label in labels.items() if label.endswith("-latest")}
    assert floating == {}, f"release jobs on a moving image label: {floating}"
    assert len(set(labels.values())) == 1, f"release jobs disagree on the image: {labels}"


def test_pull_request_ci_runs_linux_jobs_on_the_release_image() -> None:
    release_image = set(_runner_labels(PUBLISH).values())
    offenders = {
        f"{path.name}:{name}": label
        for path in PR_CI
        for name, label in _runner_labels(path).items()
        if label.startswith("ubuntu") and {label} != release_image
    }
    assert offenders == {}, (
        f"pull-request CI runs on {offenders}, the release runs on {release_image}; "
        "a tag would be the first run on its image"
    )


def _triggered_by_tag(path: Path) -> bool:
    document = _load(path)
    # PyYAML reads the bare `on:` key as the boolean True (YAML 1.1).
    triggers = document.get("on", document.get(True))
    push = triggers.get("push") if isinstance(triggers, dict) else None
    return isinstance(push, dict) and "tags" in push


def test_tag_triggered_workflows_restore_no_cache() -> None:
    tagged = [path for path in sorted(WORKFLOW_DIR.glob("*.yml")) if _triggered_by_tag(path)]
    assert PUBLISH in tagged, "precondition: publish-pypi.yml is triggered by a tag"
    offenders = []
    for path in tagged:
        for name, job in _jobs(path).items():
            for step in _steps(job):
                uses = str(step.get("uses", ""))
                cached = (step.get("with") or {}).get("cache")
                if uses.startswith("actions/cache") or (
                    uses.startswith("actions/setup-") and cached
                ):
                    offenders.append(f"{path.name}:{name}:{step.get('name', uses)}")
    assert offenders == [], (
        f"tag-triggered steps restore a cache written by branch runs: {offenders}"
    )


def test_release_run_scripts_take_context_values_through_env() -> None:
    """Only `env.*` values defined in this workflow may appear in a `run:` script.

    `${{ }}` is substituted before the shell parses the line, so quoting it does
    not protect it. The file's own comment on the `Resolve tag` step states
    the rule; this holds every other step to it. An allowed `env.*` value is
    not necessarily static: publish-container's `IMAGE_NAME` comes from
    `github.repository`, which only the repository owner controls.
    """
    offenders = []
    for name, job in _jobs(PUBLISH).items():
        for step in _steps(job):
            for expression in _EXPRESSION.findall(str(step.get("run", ""))):
                if not expression.strip().startswith("env."):
                    offenders.append(f"{name}:{step.get('name')}: ${{{{{expression}}}}}")
    assert offenders == [], f"context values interpolated into run scripts: {offenders}"


def test_attestations_write_is_granted_only_to_jobs_that_attest() -> None:
    offenders = []
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        for name, job in _jobs(path).items():
            permissions = job.get("permissions")
            if not isinstance(permissions, dict) or permissions.get("attestations") != "write":
                continue
            if not any(
                str(step.get("uses", "")).startswith("actions/attest") for step in _steps(job)
            ):
                offenders.append(f"{path.name}:{name}")
    assert offenders == [], f"attestations: write granted to jobs with no attest step: {offenders}"


def test_pull_request_sample_gate_matches_the_publish_gate() -> None:
    publish_runs = _collector_runs(_jobs(PUBLISH)["release-bundle"])
    publish_gates = {gate for run in publish_runs for gate in _FAIL_ON.findall(run)}
    assert publish_gates == {"conditional"}, f"precondition: publish gates on {publish_gates}"
    ci_runs = _collector_runs(_jobs(WORKFLOW_DIR / "github-ci-cd.yml")["sample-bundle"])
    assert ci_runs, "precondition: the sample-bundle job runs the collector"
    ci_gates = [_FAIL_ON.findall(run) for run in ci_runs]
    assert all(gates == ["conditional"] for gates in ci_gates), (
        f"sample-bundle gates on {ci_gates}; publish runs the same sample with "
        "--fail-on conditional, so a weaker CI gate lets a tag fail on it"
    )
