"""Determinism guardrail: identical input must produce identical bundles.

The collector's public contract (README, `docs/limitations.md §8`) promises
that two back-to-back runs on identical inputs produce byte-for-byte
identical `bundle.json` **after stripping** the three intentionally
per-run fields: `generated_at`, `evaluated_at`, `bundle_id`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.domain.models import Application, ReleaseContext

_VOLATILE_KEYS = {
    "bundle_id",
    "generated_at",
    "evaluated_at",
    "collected_at",
}


def _strip_volatile(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {k: _strip_volatile(v) for k, v in payload.items() if k not in _VOLATILE_KEYS}
    if isinstance(payload, list):
        return [_strip_volatile(item) for item in payload]
    return payload


@pytest.mark.integration
def test_sample_release_bundle_is_deterministic(tmp_path: Path, sample_release_root: Path) -> None:
    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")

    def _run(output_dir: Path) -> dict[str, Any]:
        run_pipeline(
            application=app_,
            release=release,
            artifacts_dirs=[sample_release_root / "artifacts"],
            attestations_dirs=[sample_release_root / "attestations"],
            output_dir=output_dir,
        )
        payload: dict[str, Any] = json.loads(
            (output_dir / "bundle.json").read_text(encoding="utf-8")
        )
        return payload

    first = _run(tmp_path / "run-a")
    second = _run(tmp_path / "run-b")

    # Volatile fields are proof of a fresh run.
    assert first["bundle_id"] != second["bundle_id"]
    # `generated_at` is asserted as *present and non-empty* rather than
    # different: two runs can legitimately land in the same microsecond, so a
    # strict inequality would be flaky. The previous form was
    # `a != b or a`, whose right operand is a non-empty ISO string and is
    # therefore always truthy — the assertion could never fail.
    assert isinstance(first["generated_at"], str) and first["generated_at"]
    assert isinstance(second["generated_at"], str) and second["generated_at"]

    # Everything else must be identical.
    assert _strip_volatile(first) == _strip_volatile(second)


@pytest.mark.integration
def test_sample_release_bundle_is_stable_across_artifact_reorder(
    tmp_path: Path, sample_release_root: Path
) -> None:
    """Filesystem iteration order must not leak into the bundle. We simulate
    this by copying artifacts into two directories where the inode order
    differs."""
    import shutil

    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")

    dir_a = tmp_path / "arts-a"
    dir_b = tmp_path / "arts-b"
    dir_a.mkdir()
    dir_b.mkdir()

    src = sample_release_root / "artifacts"
    files = sorted(src.iterdir())
    for f in files:
        shutil.copy2(f, dir_a / f.name)
    for f in reversed(files):
        shutil.copy2(f, dir_b / f.name)

    def _run(artifacts_dir: Path, output_dir: Path) -> dict[str, Any]:
        run_pipeline(
            application=app_,
            release=release,
            artifacts_dirs=[artifacts_dir],
            attestations_dirs=[sample_release_root / "attestations"],
            output_dir=output_dir,
        )
        payload: dict[str, Any] = json.loads(
            (output_dir / "bundle.json").read_text(encoding="utf-8")
        )
        return payload

    first = _run(dir_a, tmp_path / "out-a")
    second = _run(dir_b, tmp_path / "out-b")

    # Evidence ordering may follow filesystem iteration, but the set of
    # evidence_type+summary fingerprints must match.
    fp_a = sorted((e["evidence_type"], e["summary"] or "") for e in first["evidence"])
    fp_b = sorted((e["evidence_type"], e["summary"] or "") for e in second["evidence"])
    assert fp_a == fp_b

    # Control evaluations must be identical modulo volatile keys.
    assert _strip_volatile(first["control_evaluations"]) == _strip_volatile(
        second["control_evaluations"]
    )

    # Summary must be identical (release_status drives release gate).
    assert first["summary"] == second["summary"]


# ---------------------------------------------------------------------------
# Determinism must hold under every regulatory profile (DET-01)
#
# `--profile cra-2026` anchored its reporting deadlines on
# `datetime.now(tz=UTC)` and wrote them into evidence[*].metadata.cra, which
# `normalize_bundle` never reached. Two identical runs therefore produced
# different structural hashes — with microsecond precision, always — which
# made `verify --expected` unusable exactly under the regulatory profile, and
# left any in-toto statement built over a CRA bundle permanently
# unverifiable. The old test only ever ran the default profile.
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("profile", ["none", "cra-2026", "fedramp-20x"])
def test_structural_hash_is_stable_under_every_profile(
    tmp_path: Path, sample_release_root: Path, profile: str
) -> None:
    from evidence_collector.application.integrity import structural_sha256

    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")

    def _hash(output_dir: Path) -> str:
        run_pipeline(
            application=app_,
            release=release,
            artifacts_dirs=[sample_release_root / "artifacts"],
            attestations_dirs=[sample_release_root / "attestations"],
            output_dir=output_dir,
            artifact_root=sample_release_root.parent.parent,
            profile=profile,
        )
        return structural_sha256(output_dir / "bundle.json")

    assert _hash(tmp_path / "a") == _hash(tmp_path / "b")


@pytest.mark.integration
def test_cra_profile_keeps_its_deadlines_in_the_written_bundle(
    tmp_path: Path, sample_release_root: Path
) -> None:
    """Stripping happens at hash time only — the artifact must keep the content.

    Guards against "fixing" determinism by deleting the regulatory annotation
    the profile exists to produce.
    """
    run_pipeline(
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        artifacts_dirs=[sample_release_root / "artifacts"],
        output_dir=tmp_path / "cra",
        profile="cra-2026",
    )
    payload = json.loads((tmp_path / "cra" / "bundle.json").read_text(encoding="utf-8"))
    cra = payload["evidence"][0]["metadata"]["cra"]
    assert cra["disclosure_deadline"]
    assert cra["reporting_deadlines"]["early_warning"]
    assert cra["reporting_deadlines"]["full_notification"]
    assert cra["reporting_deadlines"]["final_report"]["window_days"]
    assert cra["exploitation_status"]
