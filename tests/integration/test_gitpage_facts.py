"""The landing page facts injected at Pages build time still match the CLI.

deploy-github-pages.yml runs the CLI on the sample release and on the sample
without its rollback plan and artifact signature, then rewrites and checks the
marked facts in gitpage/index.html with gitpage/tools/page_facts.py. That
workflow only runs on pull requests that touch the landing page, so these tests
run the same steps in regular CI: a change elsewhere that removes a marker or
turns the example into another verdict fails here instead of on the next
deploy from main.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector import __version__
from evidence_collector.cli.main import app

REPO_ROOT = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location(
    "page_facts", REPO_ROOT / "gitpage" / "tools" / "page_facts.py"
)
assert _SPEC is not None and _SPEC.loader is not None
page_facts = importlib.util.module_from_spec(_SPEC)
# dataclasses resolves the module's annotations through sys.modules.
sys.modules[_SPEC.name] = page_facts
_SPEC.loader.exec_module(page_facts)


def _run(output_dir: Path, attestations_dir: Path, sample_release_root: Path) -> int:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abc1234",
            "--branch",
            "main",
            "--artifacts-dir",
            str(sample_release_root / "artifacts"),
            "--attestations-dir",
            str(attestations_dir),
            "--output-dir",
            str(output_dir),
        ],
    )
    return result.exit_code


@pytest.fixture
def page_inputs(tmp_path: Path, sample_release_root: Path) -> list[str]:
    """Generate the workflow's inputs and return the page_facts arguments."""
    assert _run(tmp_path / "sample", sample_release_root / "attestations", sample_release_root) == 0

    example_attestations = tmp_path / "example-attestations"
    example_attestations.mkdir()
    for path in (sample_release_root / "attestations").glob("*.yaml"):
        if path.name not in {"rollback_plan.yaml", "artifact_signature.yaml"}:
            shutil.copy(path, example_attestations / path.name)
    assert _run(tmp_path / "example", example_attestations, sample_release_root) == 2

    schema = CliRunner().invoke(app, ["schema"])
    assert schema.exit_code == 0
    (tmp_path / "schema.json").write_text(schema.stdout, encoding="utf-8")

    page = tmp_path / "index.html"
    shutil.copy(REPO_ROOT / "gitpage" / "index.html", page)
    return [
        "--page",
        str(page),
        "--sample",
        str(tmp_path / "sample" / "bundle.json"),
        "--example",
        str(tmp_path / "example" / "bundle.json"),
        "--schema",
        str(tmp_path / "schema.json"),
        "--version",
        __version__,
    ]


@pytest.mark.integration
def test_injected_page_matches_the_cli(page_inputs: list[str]) -> None:
    assert page_facts.main(["inject", *page_inputs]) == 0
    assert page_facts.main(["check", *page_inputs]) == 0

    page = Path(page_inputs[1]).read_text(encoding="utf-8")
    assert f'data-fact="version">v{__version__}<' in page
    assert 'data-fact="example.status">not_ready<' in page


@pytest.mark.integration
def test_check_fails_on_a_stale_fact(page_inputs: list[str]) -> None:
    assert page_facts.main(["inject", *page_inputs]) == 0
    page = Path(page_inputs[1])
    text = page.read_text(encoding="utf-8")
    stale = text.replace(f'data-fact="version">v{__version__}<', 'data-fact="version">v0.0.1<')
    assert stale != text
    page.write_text(stale, encoding="utf-8")

    assert page_facts.main(["check", *page_inputs]) == 1


@pytest.mark.integration
def test_check_fails_when_the_example_is_not_not_ready(page_inputs: list[str]) -> None:
    ready_as_example = list(page_inputs)
    ready_as_example[5] = page_inputs[3]  # the sample bundle, which is ready

    assert page_facts.main(["check", *ready_as_example]) == 1
