"""Deterministic SHA-256 snapshot of the canonical sample release bundle.

The collector promises that the same inputs produce the same bundle once
the documented volatile fields (``bundle_id``, ``generated_at``, per-
evidence ``collected_at``, per-control ``evaluated_at``) are stripped.
Two existing tests cover that promise *within* a run:

* :mod:`tests.integration.test_determinism` checks two back-to-back runs
  agree on everything but the volatile fields.
* the ``cross-os-determinism`` CI job checks Linux vs Windows runners
  agree on the structural SHA-256.

What was missing was a snapshot that locks the structural SHA-256 of the
canonical ``examples/sample_release`` bundle across **time**. Any change
to parsers, normalizers, scoring, the canonical JSON encoder, or the
catalog will break this test and force an intentional snapshot update.

The expected SHA lives in
``tests/fixtures/sample_release_snapshot.sha256`` so a regeneration is a
single-line diff that shows up in code review.

Workflow when the snapshot legitimately needs to change:

1. Run ``pytest tests/integration/test_bundle_snapshot.py`` — the test
   prints the new digest.
2. Replace the contents of ``tests/fixtures/sample_release_snapshot.sha256``
   with the new digest.
3. Explain *why* the snapshot changed in the PR description and link the
   change in ``CHANGELOG.md``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from evidence_collector.application.integrity import structural_sha256
from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.models import Application, ReleaseContext

SNAPSHOT_FILE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "sample_release_snapshot.sha256"
)


def _produce_sample_bundle(output_dir: Path, sample_release_root: Path) -> Path:
    """Reproduce the canonical sample bundle into ``output_dir`` and return its path."""
    application = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    run_pipeline(
        application=application,
        release=release,
        artifacts_dirs=[sample_release_root / "artifacts"],
        attestations_dirs=[sample_release_root / "attestations"],
        output_dir=output_dir,
    )
    bundle_path = output_dir / "bundle.json"
    assert bundle_path.is_file(), f"sample run produced no bundle at {bundle_path}"
    return bundle_path


def _read_expected_snapshot() -> str | None:
    if not SNAPSHOT_FILE.is_file():
        return None
    raw = SNAPSHOT_FILE.read_text(encoding="utf-8").strip()
    # Allow lines with comments so future readers can find the rationale.
    digest_lines = [
        line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")
    ]
    return digest_lines[0] if digest_lines else None


@pytest.mark.integration
def test_sample_release_bundle_sha256_snapshot(tmp_path: Path, sample_release_root: Path) -> None:
    """Structural SHA-256 of the sample bundle must match the snapshot fixture."""
    bundle_path = _produce_sample_bundle(tmp_path, sample_release_root)
    actual = structural_sha256(bundle_path)

    expected = _read_expected_snapshot()

    if expected is None:
        pytest.fail(
            "tests/fixtures/sample_release_snapshot.sha256 is empty or missing.\n"
            "Populate it with the digest below and commit:\n\n"
            f"  {actual}\n\n"
            "Note that any future bundle change will then need to update this "
            "fixture with rationale in the PR description."
        )

    assert actual == expected, (
        "Structural bundle drift detected.\n"
        f"  expected (snapshot): {expected}\n"
        f"  actual (this run):   {actual}\n"
        "Either the change is intentional — update "
        "tests/fixtures/sample_release_snapshot.sha256 and explain in the "
        "CHANGELOG — or a regression slipped in."
    )
