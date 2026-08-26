"""A bundle must say which control catalog produced its verdict.

Reproduced before this existed: the same artifacts, the same command, and only
`--catalog` different, gave `not_ready` with exit 2 against the shipped catalog
and `conditional` with exit 0 against one whose required evidence types had been
moved to recommended. Exit 0 passes a CI gate. Nothing in either bundle said
which catalog had been used, so an auditor holding the second one could not tell
it had been evaluated against a relaxed standard.

`verify --expected` proves a bundle has not changed since it was generated. This
is the other half: against what.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from evidence_collector.controls import catalog_with_provenance
from evidence_collector.controls.catalog import bundled_catalog_path
from evidence_collector.domain.models import BUNDLE_SCHEMA_VERSION

PACKAGED_CATALOG = "catalog.yaml"


def _relaxed_catalog(tmp_path: Path, name: str = "relaxed.yaml") -> Path:
    """The shipped catalog with every requirement demoted to a recommendation.

    This is the weakening that survives validation. Emptying both lists is
    already refused by `ControlDefinition`, which is a real control and stays
    verified in `test_catalog.py`; moving `required` into `recommended` keeps
    every control well-formed and turns `missing` into `partial`, which is what
    flips the verdict and the exit code.
    """
    data = yaml.safe_load(bundled_catalog_path(PACKAGED_CATALOG).read_text(encoding="utf-8"))
    for control in data["controls"]:
        required = control.get("required_evidence_types") or []
        recommended = control.get("recommended_evidence_types") or []
        control["recommended_evidence_types"] = sorted(set(recommended) | set(required))
        control["required_evidence_types"] = []
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def test_the_packaged_catalog_is_recorded_as_builtin() -> None:
    _, ref = catalog_with_provenance(None)
    assert ref.origin == "builtin"
    assert ref.name == PACKAGED_CATALOG
    assert ref.control_count > 0


def test_an_operator_supplied_catalog_is_recorded_as_custom(tmp_path: Path) -> None:
    controls, ref = catalog_with_provenance(_relaxed_catalog(tmp_path))
    assert ref.origin == "custom"
    assert ref.name == "relaxed.yaml"
    assert ref.control_count == len(controls)


def test_a_custom_catalog_named_like_the_packaged_one_is_still_custom(tmp_path: Path) -> None:
    """The case the name alone cannot answer.

    `catalog.yaml` is both the packaged default and the likeliest name for an
    operator's own file — `_coerce_path` carries a warning about exactly this
    collision. If `origin` were derived from the filename, the substitution
    this whole record exists to surface would be the one it could not show.
    """
    _, ref = catalog_with_provenance(_relaxed_catalog(tmp_path, name=PACKAGED_CATALOG))
    assert ref.name == PACKAGED_CATALOG
    assert ref.origin == "custom"


def test_a_packaged_catalog_reached_by_path_is_still_builtin() -> None:
    """How the argument was spelled is not what a reader needs to know."""
    _, ref = catalog_with_provenance(bundled_catalog_path("catalog-ssdf-1.2.yaml"))
    assert ref.origin == "builtin"
    assert ref.name == "catalog-ssdf-1.2.yaml"


def test_the_digest_is_the_file_an_auditor_can_hash_themselves(tmp_path: Path) -> None:
    """Taken over the bytes, so `sha256sum` on the same file matches.

    Deliberately not over the parsed model: two YAML files differing only in
    key order or comments describe the same controls, and someone comparing a
    bundle against a published catalog is asking about the file.
    """
    catalog = _relaxed_catalog(tmp_path)
    _, ref = catalog_with_provenance(catalog)
    assert ref.sha256 == hashlib.sha256(catalog.read_bytes()).hexdigest()


def test_two_different_catalogs_do_not_share_a_digest(tmp_path: Path) -> None:
    _, packaged = catalog_with_provenance(None)
    _, relaxed = catalog_with_provenance(_relaxed_catalog(tmp_path))
    assert packaged.sha256 != relaxed.sha256


def test_the_same_catalog_gives_the_same_digest_every_time(tmp_path: Path) -> None:
    """The record has to be stable, or it moves the structural hash per run."""
    catalog = _relaxed_catalog(tmp_path)
    first = catalog_with_provenance(catalog)[1]
    second = catalog_with_provenance(catalog)[1]
    assert first.model_dump() == second.model_dump()


def test_the_bundle_contract_version_announces_the_new_field() -> None:
    """A validator pinned to 2.0.0 rejects a bundle carrying `catalog`.

    The published schema is `additionalProperties: false` at every level, so by
    this contract's own rules the field has to come with a version move — the
    thing `collection_errors` failed to do when it landed.
    """
    assert BUNDLE_SCHEMA_VERSION == "2.1.0"


@pytest.mark.parametrize("origin", ["builtin", "custom"])
def test_the_recorded_catalog_never_carries_a_directory_component(
    tmp_path: Path, origin: str
) -> None:
    """Which directory the operator keeps their catalog in is not the bundle's business.

    It is the same class of detail `--artifact-root` exists to keep out of a
    published bundle, and the digest identifies the catalog without it.
    """
    nested = tmp_path / "internal" / "compliance" / "secret-project"
    nested.mkdir(parents=True)
    source = None if origin == "builtin" else _relaxed_catalog(nested)

    _, ref = catalog_with_provenance(source)

    assert "/" not in ref.name
    assert "\\" not in ref.name
    assert "secret-project" not in ref.name


def test_a_relaxed_catalog_produces_a_distinguishable_bundle(tmp_path: Path) -> None:
    """The finding itself, end to end.

    Same evidence, same command, only `--catalog` different. The verdict and
    the exit code move — which is legitimate, since customising the catalog is
    a supported feature — but the two bundles must not be interchangeable to
    whoever receives them.
    """
    from evidence_collector.application.orchestrator import build_bundle
    from evidence_collector.domain.models import Application, ReleaseContext

    application = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")

    shipped, _ = build_bundle(application, release, [])
    relaxed, _ = build_bundle(application, release, [], catalog_path=_relaxed_catalog(tmp_path))

    assert shipped.catalog is not None
    assert relaxed.catalog is not None
    assert shipped.catalog.origin == "builtin"
    assert relaxed.catalog.origin == "custom"
    assert shipped.catalog.sha256 != relaxed.catalog.sha256

    # The relaxation is what changes the verdict, so the record has to travel
    # with it — otherwise the softer verdict arrives with nothing to explain it.
    assert shipped.summary.release_status != relaxed.summary.release_status


def test_the_catalog_record_is_inside_the_structural_hash(tmp_path: Path) -> None:
    """Otherwise `verify --expected` would accept a swapped catalog silently.

    The record is only worth as much as its resistance to being edited out, and
    the structural hash is what a consumer checks the bundle with.
    """
    import json

    from evidence_collector.application.integrity import structural_sha256
    from evidence_collector.application.orchestrator import build_bundle
    from evidence_collector.domain.models import Application, ReleaseContext

    bundle, _ = build_bundle(
        Application(name="payments-api", repository="acme/payments-api"),
        ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        [],
    )
    payload = json.loads(bundle.model_dump_json())

    original = tmp_path / "bundle.json"
    original.write_text(json.dumps(payload), encoding="utf-8")

    tampered_payload = json.loads(json.dumps(payload))
    tampered_payload["catalog"]["origin"] = "builtin"
    tampered_payload["catalog"]["name"] = "catalog.yaml"
    tampered_payload["catalog"]["sha256"] = "0" * 64
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(tampered_payload), encoding="utf-8")

    assert structural_sha256(original) != structural_sha256(tampered)
