"""Structural checks on the GitHub workflows that CI cannot exercise.

`publish-pypi.yml` runs only on a release tag, so a mistake in it is found by
the release it breaks. The 3.0.0 run failed that way: the SBOM job, moved out
of the signing job without a checkout, still asked `actions/setup-python` for
a pip cache. The cache keys on a dependency file in the workspace, found none,
and the job failed before generating anything, which skipped signing and
publication.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = sorted((Path(__file__).resolve().parents[2] / ".github" / "workflows").glob("*.yml"))


def _jobs(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = document.get("jobs", {}) if isinstance(document, dict) else {}
    return jobs if isinstance(jobs, dict) else {}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_a_cached_setup_python_follows_a_checkout(workflow: Path) -> None:
    for job_name, job in _jobs(workflow).items():
        checked_out = False
        for step in job.get("steps", []) if isinstance(job, dict) else []:
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout@"):
                checked_out = True
            if uses.startswith("actions/setup-python@") and (step.get("with") or {}).get("cache"):
                assert checked_out, (
                    f"{workflow.name}:{job_name} asks setup-python for a cache before any "
                    "checkout, so there is no dependency file to key it on"
                )


def test_the_workflow_directory_was_found() -> None:
    assert WORKFLOWS, "no workflow files found; the checks above would pass vacuously"
