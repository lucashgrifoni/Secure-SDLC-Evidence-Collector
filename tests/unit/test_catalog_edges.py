"""Edge-case tests for control-catalog loading.

Covers misuse / misconfiguration scenarios for catalogs loaded via
`--catalog`, plus the happy-path invariants of the packaged default.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from evidence_collector.controls.catalog import (
    bundled_catalog_names,
    bundled_catalog_path,
    catalog_from_source,
    default_catalog,
    load_catalog,
)
from evidence_collector.domain.enums import ControlFramework, EvidenceType

_VALID_CONTROL = """\
controls:
  - control_id: "TEST-1"
    framework: "ORG_INTERNAL"
    name: "Test control"
    description: "For unit tests."
    criticality: "high"
    required_evidence_types: ["sast_scan"]
    recommended_evidence_types: []
"""


def test_default_catalog_has_expected_size() -> None:
    controls = default_catalog()
    assert len(controls) == 13
    ids = {c.control_id for c in controls}
    assert "SSDF-PW.7" in ids  # SAST
    assert "SAMM-VERIF-ST-1" in ids  # SAMM ST


def test_default_catalog_does_not_include_ssdf_pw6() -> None:
    """T6.4 guard: SSDF-PW.6 belongs to the 1.2 catalog only.

    Promoting it into the default would silently raise the bar for
    every existing user — exactly the regression the opt-in design is
    meant to prevent.
    """
    ids = {c.control_id for c in default_catalog()}
    assert "SSDF-PW.6" not in ids


def test_bundled_ssdf_12_catalog_loads_cleanly() -> None:
    path = bundled_catalog_path("catalog-ssdf-1.2.yaml")
    controls = load_catalog(path)
    # All control_ids unique (mirrors the loader's invariant).
    ids = [c.control_id for c in controls]
    assert len(ids) == len(set(ids))


def test_ssdf_12_catalog_promotes_attestation_to_required_on_ps3() -> None:
    """SSDF 1.2 refinement: PS.3 requires SBOM *and* artifact_attestation."""
    path = bundled_catalog_path("catalog-ssdf-1.2.yaml")
    controls = {c.control_id: c for c in load_catalog(path)}
    ps3 = controls["SSDF-PS.3"]
    assert EvidenceType.SBOM in ps3.required_evidence_types
    assert EvidenceType.ARTIFACT_ATTESTATION in ps3.required_evidence_types


def test_ssdf_12_catalog_adds_pw6_control() -> None:
    """SSDF 1.2 introduces PW.6 (build-process security)."""
    path = bundled_catalog_path("catalog-ssdf-1.2.yaml")
    controls = {c.control_id: c for c in load_catalog(path)}
    assert "SSDF-PW.6" in controls
    assert EvidenceType.ARTIFACT_ATTESTATION in controls["SSDF-PW.6"].required_evidence_types


def test_bundled_catalog_path_raises_for_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        bundled_catalog_path("catalog-does-not-exist.yaml")


def test_default_catalog_frameworks_are_subset_of_enum() -> None:
    frameworks = {c.framework for c in default_catalog()}
    assert frameworks.issubset(
        {
            ControlFramework.NIST_SSDF,
            ControlFramework.ORG_INTERNAL,
            ControlFramework.OWASP_SAMM,
        }
    )


def test_load_valid_catalog_from_disk(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(_VALID_CONTROL, encoding="utf-8")
    assert len(load_catalog(f)) == 1


def test_catalog_rejects_missing_required_field(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(
        """\
controls:
  - control_id: "TEST-1"
    framework: "ORG_INTERNAL"
    name: "Test control"
    criticality: "high"
    required_evidence_types: ["sast_scan"]
""",
        encoding="utf-8",
    )
    # `description` is required on ControlDefinition.
    with pytest.raises(Exception):  # noqa: B017  # Pydantic ValidationError subclass  # Pydantic ValidationError
        load_catalog(f)


def test_catalog_rejects_unknown_framework(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(
        """\
controls:
  - control_id: "TEST-1"
    framework: "NOT_A_FRAMEWORK"
    name: "Test control"
    description: "..."
    criticality: "high"
    required_evidence_types: ["sast_scan"]
    recommended_evidence_types: []
""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):  # noqa: B017  # Pydantic ValidationError subclass
        load_catalog(f)


def test_catalog_rejects_invalid_criticality(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(
        """\
controls:
  - control_id: "TEST-1"
    framework: "ORG_INTERNAL"
    name: "Test control"
    description: "..."
    criticality: "apocalyptic"
    required_evidence_types: ["sast_scan"]
    recommended_evidence_types: []
""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):  # noqa: B017  # Pydantic ValidationError subclass
        load_catalog(f)


def test_catalog_rejects_invalid_evidence_type(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(
        """\
controls:
  - control_id: "TEST-1"
    framework: "ORG_INTERNAL"
    name: "Test control"
    description: "..."
    criticality: "high"
    required_evidence_types: ["not_a_real_evidence_type"]
    recommended_evidence_types: []
""",
        encoding="utf-8",
    )
    with pytest.raises(Exception):  # noqa: B017  # Pydantic ValidationError subclass
        load_catalog(f)


def test_catalog_rejects_duplicate_control_ids(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(
        """\
controls:
  - control_id: "DUP-1"
    framework: "ORG_INTERNAL"
    name: "First"
    description: "..."
    criticality: "high"
    required_evidence_types: ["sast_scan"]
    recommended_evidence_types: []
  - control_id: "DUP-1"
    framework: "ORG_INTERNAL"
    name: "Second"
    description: "..."
    criticality: "medium"
    required_evidence_types: ["sca_scan"]
    recommended_evidence_types: []
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate control_id"):
        load_catalog(f)


def test_catalog_requires_top_level_controls_key(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text("framework: NIST_SSDF\n", encoding="utf-8")
    with pytest.raises(ValueError, match="top-level 'controls'"):
        load_catalog(f)


def test_catalog_rejects_non_list_controls(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text("controls: TEST-1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        load_catalog(f)


def test_catalog_rejects_invalid_yaml(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text("controls: [unterminated:\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_catalog(f)


def test_catalog_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_catalog(tmp_path / "does-not-exist.yaml")


def test_catalog_from_source_returns_default_when_none() -> None:
    assert len(catalog_from_source(None)) == len(default_catalog())


def test_catalog_from_source_returns_custom_when_given(tmp_path: Path) -> None:
    f = tmp_path / "c.yaml"
    f.write_text(_VALID_CONTROL, encoding="utf-8")
    assert len(catalog_from_source(f)) == 1


# ---------------------------------------------------------------------------
# Bundled catalogs are reachable by name from --catalog (CAT-01)
#
# Five catalogs ship with the package (default, SSDF 1.2, AI, FedRAMP 20x KSI,
# OSPS Baseline) and none of them had a CLI surface: `--catalog catalog-ai.yaml`
# raised FileNotFoundError, and `bundled_catalog_path` existed with no caller
# anywhere in `cli/`. The documented workaround was an `importlib.resources`
# incantation that breaks under pipx, containers with `python3`, and Windows —
# and docs/comparison.md taught the form that fails.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["catalog.yaml", "catalog-ai.yaml", "catalog-osps-baseline.yaml"])
def test_bundled_catalog_resolves_by_bare_name(name: str) -> None:
    controls = load_catalog(name)
    assert controls, f"{name} resolved but produced no controls"


def test_every_bundled_catalog_is_loadable_by_name() -> None:
    """Guards against shipping a catalog that the resolver cannot reach."""
    names = bundled_catalog_names()
    assert len(names) >= 5
    for name in names:
        assert load_catalog(name), name


def test_a_local_file_wins_over_a_bundled_name(tmp_path: Path, monkeypatch) -> None:
    """The filesystem is consulted first, so a local override is never shadowed."""
    local = tmp_path / "catalog-ai.yaml"
    local.write_text(
        "controls:\n"
        '  - control_id: "LOCAL-1"\n'
        '    framework: "NIST_SSDF"\n'
        '    name: "Local override"\n'
        '    description: "only in the local file"\n'
        '    criticality: "low"\n'
        '    required_evidence_types: ["sast_scan"]\n'
        "    recommended_evidence_types: []\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    controls = load_catalog("catalog-ai.yaml")
    assert [c.control_id for c in controls] == ["LOCAL-1"]


def test_unknown_catalog_error_lists_the_bundled_ones() -> None:
    """The failure must be actionable, not just 'not found'."""
    with pytest.raises(FileNotFoundError) as excinfo:
        load_catalog("does-not-exist.yaml")
    message = str(excinfo.value)
    assert "does-not-exist.yaml" in message
    for name in bundled_catalog_names():
        assert name in message


# ---------------------------------------------------------------------------
# The gate must not be substituted or bypassed silently
# ---------------------------------------------------------------------------


def test_empty_controls_list_is_refused_rather_than_passing_everything(
    tmp_path: Path,
) -> None:
    """An empty catalog made the release gate fail OPEN.

    Zero controls means zero gaps, so `build_summary` returned `ready` with
    coverage 0 and the command exited 0. A truncated or half-written catalog
    therefore passed every release with `Controls met=0 missing=0` and nothing
    to read as a warning. There is no honest verdict for "nothing was
    checked".
    """
    catalog = tmp_path / "empty.yaml"
    catalog.write_text("controls: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty 'controls' list"):
        load_catalog(catalog)


def test_bundled_fallback_warns_that_the_verdict_used_another_control_set(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--catalog catalog.yaml` from the wrong directory silently swapped the
    control set.

    `catalog.yaml` is both the default bundled name and the most likely name a
    user gives their own file. Running one directory up turned the flag into
    "evaluate against the stock 13 controls" — verdict `ready`, exit 0, with
    nothing in stdout, stderr or the bundle saying the org catalog was never
    read. A substituted control set is a substituted verdict, so the fallback
    has to say so.
    """
    monkeypatch.chdir(tmp_path)  # no catalog.yaml here
    with caplog.at_level(logging.WARNING):
        controls = load_catalog("catalog.yaml")
    assert controls, "the bundled catalog should still load"
    assert "BUNDLED" in caplog.text
    assert "catalog.yaml" in caplog.text


def test_a_real_local_file_still_wins_over_the_bundled_name(tmp_path: Path) -> None:
    """The fallback must not fire when the user's file is actually there."""
    local = tmp_path / "catalog.yaml"
    local.write_text(
        "controls:\n"
        "  - control_id: ORG-ONLY\n"
        "    framework: ORG_INTERNAL\n"
        "    name: Only control\n"
        "    description: local file wins\n"
        "    criticality: high\n"
        "    required_evidence_types: ['sast_scan']\n",
        encoding="utf-8",
    )
    controls = load_catalog(local)
    assert [c.control_id for c in controls] == ["ORG-ONLY"]
