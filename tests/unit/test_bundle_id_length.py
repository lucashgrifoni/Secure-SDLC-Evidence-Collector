"""The default bundle id fits the 200-character limit for any accepted input.

`--application` accepts 200 characters and `--release-id` 100, but the id
pasted both into one string with a 200-character cap, so a long application
name failed the run with a validation error about `bundle_id`, a field the
user never set.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from evidence_collector.application.orchestrator import _default_bundle_id
from evidence_collector.cli.main import app
from evidence_collector.domain.models import Application, ReleaseContext

SAMPLE = Path("examples/sample_release")


def test_the_longest_accepted_names_give_an_id_within_the_limit() -> None:
    application = Application(name="a" * 200, repository="acme/app")
    release = ReleaseContext(release_id="r" * 100, commit_sha="abcdef1234567890")
    bundle_id = _default_bundle_id(application, release)
    assert len(bundle_id) <= 200
    assert bundle_id.startswith("bundle-")
    assert "-aaaa" in bundle_id and "-rrrr" in bundle_id


def test_two_runs_with_the_same_long_names_get_different_ids() -> None:
    application = Application(name="a" * 200, repository="acme/app")
    release = ReleaseContext(release_id="r" * 100, commit_sha="abcdef1234567890")
    assert _default_bundle_id(application, release) != _default_bundle_id(application, release)


def test_run_accepts_a_180_character_application_name(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "run",
            "--application",
            "x" * 180,
            "--repository",
            "acme/app",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(SAMPLE / "artifacts"),
            "--output-dir",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code in {0, 1, 2}, result.output
    assert (tmp_path / "out" / "bundle.json").is_file()
