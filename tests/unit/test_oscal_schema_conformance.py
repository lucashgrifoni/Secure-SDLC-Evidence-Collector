r"""OSCAL output validates against the official NIST OSCAL 1.1.2 JSON schemas.

The schemas live in ``tests/fixtures/oscal`` (see the NOTICE there for the
source and digests). They use Unicode property escapes (``\p{L}``) that
Python's ``re`` rejects, so the ``pattern`` keyword is checked with the
``regex`` package; every other keyword uses the stock Draft 7 validator.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import regex
from jsonschema import validators
from jsonschema.exceptions import ValidationError

from evidence_collector.application.orchestrator import run_pipeline
from evidence_collector.controls.catalog import (
    bundled_catalog_names,
    bundled_catalog_path,
    load_catalog,
)
from evidence_collector.domain.enums import (
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
    EvidenceStatus,
    EvidenceType,
    ReleaseStatus,
    SubjectType,
)
from evidence_collector.domain.models import (
    Application,
    ControlDefinition,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
    EvidenceSource,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.guac import build_guac_collection
from evidence_collector.exporters.html import bundle_to_html
from evidence_collector.exporters.intoto import build_dsse_envelope, build_statement
from evidence_collector.exporters.markdown import bundle_to_markdown
from evidence_collector.exporters.oscal import (
    OscalControlTokenCollisionError,
    control_token,
    export_oscal_assessment_results,
    export_oscal_catalog,
)
from evidence_collector.exporters.report_set import export_report_set
from evidence_collector.exporters.sarif_gaps import build_gap_sarif
from evidence_collector.exporters.vex import build_openvex

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "oscal"


def _pattern(
    validator: Any, pattern: str, instance: Any, schema: dict[str, Any]
) -> Iterator[ValidationError]:
    if validator.is_type(instance, "string") and not regex.search(pattern, instance):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


_OscalValidator = validators.extend(  # type: ignore[no-untyped-call]
    jsonschema.Draft7Validator, {"pattern": _pattern}
)


def _validator(schema_file: str) -> Any:
    schema = json.loads((FIXTURES / schema_file).read_text(encoding="utf-8"))
    return _OscalValidator(schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)


def _errors(validator: Any, document: dict[str, Any]) -> list[str]:
    return [
        f"{'/'.join(map(str, error.absolute_path))}: {error.message}"
        for error in validator.iter_errors(document)
    ]


@pytest.fixture(scope="module")
def sample_results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    sample = root / "examples" / "sample_release"
    output = tmp_path_factory.mktemp("oscal-sample")
    run_pipeline(
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        artifacts_dirs=[sample / "artifacts"],
        attestations_dirs=[sample / "attestations"],
        exceptions_dirs=[sample / "exceptions"],
        output_dir=output,
        artifact_root=root,
    )
    bundle = EvidenceBundle.model_validate_json(
        (output / "bundle.json").read_text(encoding="utf-8")
    )
    return export_oscal_assessment_results(bundle)


def _embedded_plan(results: dict[str, Any]) -> dict[str, Any]:
    ar = results["assessment-results"]
    resources = {r["uuid"]: r for r in ar["back-matter"]["resources"]}
    resource = resources[ar["import-ap"]["href"].lstrip("#")]
    plan: dict[str, Any] = json.loads(base64.b64decode(resource["base64"]["value"]))
    return plan


def test_sample_assessment_results_validate_against_the_oscal_schema(
    sample_results: dict[str, Any],
) -> None:
    assert _errors(_validator("oscal_assessment-results_schema.json"), sample_results) == []


def test_embedded_assessment_plan_validates_against_the_oscal_schema(
    sample_results: dict[str, Any],
) -> None:
    plan = _embedded_plan(sample_results)
    assert _errors(_validator("oscal_assessment-plan_schema.json"), plan) == []


def test_the_schema_check_rejects_a_broken_document(sample_results: dict[str, Any]) -> None:
    broken = json.loads(json.dumps(sample_results))
    del broken["assessment-results"]["metadata"]["title"]
    broken["assessment-results"]["uuid"] = "not-a-uuid"
    errors = _errors(_validator("oscal_assessment-results_schema.json"), broken)
    assert any("'title' is a required property" in e for e in errors)
    assert any(e.startswith("assessment-results/uuid") for e in errors)


@pytest.fixture(scope="module")
def awkward_results(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Evidence ids that are not NCNames and paths of every recorded shape."""
    root = Path(__file__).resolve().parents[2]
    sample = root / "examples" / "sample_release"
    output = tmp_path_factory.mktemp("oscal-awkward")
    run_pipeline(
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        artifacts_dirs=[sample / "artifacts"],
        attestations_dirs=[sample / "attestations"],
        output_dir=output,
        artifact_root=root,
    )
    bundle = EvidenceBundle.model_validate_json(
        (output / "bundle.json").read_text(encoding="utf-8")
    )
    ids = ["scan:1", "scan/1", "1", "4", "evidence id"]
    paths = [
        "reports\\scan.json",
        "C:reports\\scan.json",
        "C:\\ci\\scan report.json",
        "/srv/ci/scan report.json",
        "artifacts/scan.json",
    ]
    renamed: dict[str, str] = {}
    evidence = []
    for index, item in enumerate(bundle.evidence):
        new_id = ids[index % len(ids)] + ("" if index < len(ids) else f"-{index}")
        renamed[item.evidence_id] = new_id
        raw = (
            item.raw.model_copy(update={"artifact_path": paths[index % len(paths)]})
            if item.raw
            else None
        )
        evidence.append(item.model_copy(update={"evidence_id": new_id, "raw": raw}))
    evaluations = [
        ev.model_copy(update={"evidence_refs": [renamed.get(r, r) for r in ev.evidence_refs]})
        for ev in bundle.control_evaluations
    ]
    awkward = bundle.model_copy(update={"evidence": evidence, "control_evaluations": evaluations})
    return export_oscal_assessment_results(awkward)


def test_awkward_ids_and_paths_validate_against_the_oscal_schema(
    awkward_results: dict[str, Any],
) -> None:
    resources = awkward_results["assessment-results"]["back-matter"]["resources"]
    assert any("rlinks" in r for r in resources), "no absolute path produced a link"
    assert any(p.get("name") == "artifact-path" for r in resources for p in r.get("props", [])), (
        "no relative path was recorded as a prop"
    )
    assert _errors(_validator("oscal_assessment-results_schema.json"), awkward_results) == []
    plan = _embedded_plan(awkward_results)
    assert _errors(_validator("oscal_assessment-plan_schema.json"), plan) == []


@pytest.mark.parametrize("with_artifacts", [True, False], ids=["artifacts-only", "no-evidence"])
def test_not_ready_assessment_results_validate_against_the_oscal_schema(
    tmp_path: Path, with_artifacts: bool
) -> None:
    # Controls with no evidence at all are the normal not_ready case; their
    # observations must not carry an empty relevant-evidence array.
    root = Path(__file__).resolve().parents[2]
    artifacts = root / "examples" / "sample_release" / "artifacts"
    empty = tmp_path / "empty"
    empty.mkdir()
    run_pipeline(
        application=Application(name="payments-api", repository="acme/payments-api"),
        release=ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890"),
        artifacts_dirs=[artifacts if with_artifacts else empty],
        attestations_dirs=[],
        output_dir=tmp_path / "out",
        artifact_root=root,
    )
    bundle = EvidenceBundle.model_validate_json(
        (tmp_path / "out" / "bundle.json").read_text(encoding="utf-8")
    )
    assert bundle.summary.release_status.value == "not_ready"
    results = export_oscal_assessment_results(bundle)
    assert _errors(_validator("oscal_assessment-results_schema.json"), results) == []
    assert _errors(_validator("oscal_assessment-plan_schema.json"), _embedded_plan(results)) == []


# ---------------------------------------------------------------------------
# Hostile but schema-valid bundles
# ---------------------------------------------------------------------------

_AWARE_IST = timezone(timedelta(hours=5, minutes=30))
_AWARE_BRT = timezone(timedelta(hours=-3))


def _hostile_evidence(evidence_id: str, raw: RawEvidenceRef | None) -> NormalizedEvidence:
    return NormalizedEvidence(
        evidence_id=evidence_id,
        evidence_type=EvidenceType.SAST_SCAN,
        source=EvidenceSource(name="tool\nname", kind="sarif"),
        producer="semgrep ✓",
        subject_type=SubjectType.COMMIT,
        subject_ref="abcdef1234567890",
        status=EvidenceStatus.PASSED,
        release_id="2026.04.10",
        commit_sha="abcdef1234567890",
        raw=raw,
    )


def _hostile_evaluation(
    control_id: str,
    status: ControlEvaluationStatus,
    refs: list[str],
    exception_refs: list[str] | None = None,
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=ControlFramework.ORG_INTERNAL,
        control_name=f"  {control_id} — naïve\nname  ",
        evaluation_status=status,
        criticality=ControlCriticality.HIGH,
        evidence_refs=refs,
        rationale=f"line one\nline two\t{control_id}  ",
        exception_refs=exception_refs or [],
        evaluated_at=datetime(2026, 4, 10, 12, 0, tzinfo=_AWARE_BRT),
    )


def _hostile_bundle(
    evaluations: list[ControlEvaluation],
    evidence: list[NormalizedEvidence],
    exceptions: list[EvidenceException] | None = None,
    generated_at: datetime | None = None,
) -> EvidenceBundle:
    def count(status: ControlEvaluationStatus) -> int:
        return sum(1 for e in evaluations if e.evaluation_status is status)

    return EvidenceBundle(
        bundle_id="bundle hostile\n1",
        generated_at=generated_at or datetime(2026, 4, 10, 18, 30, tzinfo=_AWARE_IST),
        application=Application(
            name="pay ments\napi", repository="acme/pay ments", environment="prod 1"
        ),
        release=ReleaseContext(release_id=" 2026.04.10 ", commit_sha="abcdef1234567890"),
        evidence=evidence,
        control_evaluations=evaluations,
        exceptions=exceptions or [],
        summary=Summary(
            evidence_coverage_score=0,
            confidence_score=0,
            release_status=ReleaseStatus.NOT_READY,
            total_controls=len(evaluations),
            controls_met=count(ControlEvaluationStatus.MET),
            controls_partial=count(ControlEvaluationStatus.PARTIAL),
            controls_missing=count(ControlEvaluationStatus.MISSING),
            controls_waived=count(ControlEvaluationStatus.WAIVED),
            controls_not_applicable=count(ControlEvaluationStatus.NOT_APPLICABLE),
        ),
    )


def _odd_waiver(exception_id: str, control_id: str) -> EvidenceException:
    return EvidenceException(
        exception_id=exception_id,
        control_id=control_id,
        approver="  lead@example.com\n",
        approved_at=datetime(2026, 1, 1, tzinfo=_AWARE_BRT),
        expires_at=datetime(2026, 12, 31, 23, 0, tzinfo=_AWARE_IST),
        justification="  Compensating control\nrecorded in the register.  ",
        reference=" ",
    )


def _hostile_cases() -> dict[str, EvidenceBundle]:
    raws = [
        RawEvidenceRef(artifact_uri="http://["),
        RawEvidenceRef(artifact_uri="relative/thing.json"),
        RawEvidenceRef(artifact_uri="https://ci.example/a b?x=1#frag"),
        RawEvidenceRef(artifact_path="C:reports\\scan.json"),
        RawEvidenceRef(artifact_path="\\\\server\\share\\scan report.json"),
        RawEvidenceRef(artifact_path="C:\\ci\\relatório ñ.json", integrity_hash="sha256:zz"),
        RawEvidenceRef(artifact_path="/srv/ci/a\nb.json", content_type=" "),
        RawEvidenceRef(artifact_path="reports\\scan.json"),
    ]
    odd_ids = ["scan:1", "scan/1", "1", "évidence\nid", "scan_1", "scan 1"]
    evidence = [
        _hostile_evidence(odd_ids[i] if i < len(odd_ids) else f"extra {i}", raw)
        for i, raw in enumerate(raws)
    ]
    ids = [e.evidence_id for e in evidence]
    # Odd ids that stay distinct as tokens. Ids that differ only by case or
    # "."/"-" (ORG.BUILD and ORG-BUILD) are refused; see the collision tests.
    control_ids = [
        "1",
        "ORG:BUILD",
        "custom control",
        "ORG.BUILD",
        "ORG_BUILD",
        "org.build-2",
        "Ω-7",
    ]
    statuses = list(ControlEvaluationStatus)
    evaluations = []
    for i, cid in enumerate(control_ids):
        status = statuses[i % len(statuses)]
        waived = status is ControlEvaluationStatus.WAIVED
        evaluations.append(
            _hostile_evaluation(cid, status, ids[i::3], ["EXC 1\n", "exc:2"] if waived else None)
        )
    waived_id = next(
        e.control_id for e in evaluations if e.evaluation_status is ControlEvaluationStatus.WAIVED
    )
    waivers = [_odd_waiver("EXC 1\n", waived_id), _odd_waiver("exc:2", waived_id)]
    return {
        "no-evaluations": _hostile_bundle([], []),
        "evidence-without-evaluations": _hostile_bundle([], evidence[:3]),
        "hostile-everything": _hostile_bundle(evaluations, evidence, waivers),
        "naive-timestamp": _hostile_bundle(
            evaluations[:2], evidence, generated_at=datetime(2026, 4, 10, 23, 59, 59)
        ),
    }


_HOSTILE = _hostile_cases()
_HREF = regex.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")


def _walk(node: Any, key: str) -> Iterator[Any]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            yield from _walk(v, key)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, key)


@pytest.mark.parametrize("case", sorted(_HOSTILE))
def test_hostile_bundles_validate_against_the_oscal_schemas(case: str) -> None:
    results = export_oscal_assessment_results(_HOSTILE[case])
    plan = _embedded_plan(results)
    assert _errors(_validator("oscal_assessment-results_schema.json"), results) == []
    assert _errors(_validator("oscal_assessment-plan_schema.json"), plan) == []
    # The schemas declare uri-reference, but jsonschema checks that format only
    # with an optional package; hold every href to RFC 3986 characters here.
    for document in (results, plan):
        for href in _walk(document, "href"):
            assert _HREF.match(href), href


@pytest.mark.parametrize("case", sorted(_HOSTILE))
def test_every_exporter_survives_hostile_bundles(case: str, tmp_path: Path) -> None:
    bundle = _HOSTILE[case]
    assert "assessment-results" in export_oscal_assessment_results(bundle)
    guac = build_guac_collection(bundle)
    assert len(guac["documents"]) == len(bundle.evidence)
    assert "@context" in build_openvex(bundle, now=datetime(2026, 4, 11, tzinfo=UTC))
    assert build_gap_sarif(bundle)["version"] == "2.1.0"
    assert build_dsse_envelope(build_statement(bundle))["payload"]
    assert bundle.bundle_id.split()[0] in bundle_to_markdown(bundle)
    assert "<html" in bundle_to_html(bundle)
    report = export_report_set(bundle, tmp_path)
    assert report.json_path.is_file() and report.markdown_path.is_file()


def test_timestamps_are_converted_to_utc_not_relabelled() -> None:
    results = export_oscal_assessment_results(_HOSTILE["hostile-everything"])
    # 18:30 at +05:30 is 13:00 UTC.
    assert results["assessment-results"]["metadata"]["last-modified"].startswith(
        "2026-04-10T13:00:00"
    )
    risk = results["assessment-results"]["results"][0]["risks"][0]
    # 23:00 at +05:30 on 31 Dec is 17:30 UTC.
    assert risk["deadline"].startswith("2026-12-31T17:30:00")
    naive = export_oscal_assessment_results(_HOSTILE["naive-timestamp"])
    assert naive["assessment-results"]["metadata"]["last-modified"].startswith(
        "2026-04-10T23:59:59"
    )


def _control(control_id: str) -> ControlDefinition:
    return ControlDefinition(
        control_id=control_id,
        framework=ControlFramework.ORG_INTERNAL,
        name="n",
        description="d",
        criticality=ControlCriticality.HIGH,
        required_evidence_types=[EvidenceType.SBOM],
    )


def _catalog_ids(catalog: dict[str, Any]) -> dict[str, str]:
    return {
        next(p["value"] for p in c["props"] if p["name"] == "control_id"): c["id"]
        for g in catalog["catalog"]["groups"]
        for c in g["controls"]
    }


_TOKEN = regex.compile(r"^(\p{L}|_)(\p{L}|\p{N}|[.\-_])*$")


def test_control_tokens_stay_distinct_and_keep_builtin_ids() -> None:
    results = export_oscal_assessment_results(_HOSTILE["hostile-everything"])
    result = results["assessment-results"]["results"][0]
    selected = [
        c["control-id"]
        for c in result["reviewed-controls"]["control-selections"][0]["include-controls"]
    ]
    assert len(set(selected)) == len(selected) == 7
    assert {f["target"]["target-id"] for f in result["findings"]} == set(selected)
    catalog = export_oscal_catalog(
        [_control(cid) for cid in ["SSDF-PS.3", "ORG-CODE-REVIEW", "1", "ORG:BUILD"]]
    )
    ids = [c["id"] for g in catalog["catalog"]["groups"] for c in g["controls"]]
    assert ids[:2] == ["ssdf-ps-3", "org-code-review"]
    assert all(_TOKEN.match(i) for i in ids), ids


def test_every_token_in_a_document_is_the_token_of_its_own_id() -> None:
    # Findings, reviewed-controls, the embedded plan and the catalog all use
    # the same per-id token, so a profile can select controls by it.
    bundle = _HOSTILE["hostile-everything"]
    results = export_oscal_assessment_results(bundle)
    result = results["assessment-results"]["results"][0]
    plan = _embedded_plan(results)["assessment-plan"]
    expected = [control_token(ev.control_id) for ev in bundle.control_evaluations]
    for reviewed in (result["reviewed-controls"], plan["reviewed-controls"]):
        selection = reviewed["control-selections"][0]["include-controls"]
        assert [c["control-id"] for c in selection] == expected
    assert [f["target"]["target-id"] for f in result["findings"]] == expected
    catalog = export_oscal_catalog(_control(ev.control_id) for ev in bundle.control_evaluations)
    assert _catalog_ids(catalog) == {
        ev.control_id: control_token(ev.control_id) for ev in bundle.control_evaluations
    }


def test_a_control_token_does_not_depend_on_the_other_ids_in_the_catalog() -> None:
    alone = _catalog_ids(export_oscal_catalog([_control("ORG.BUILD")]))
    crowded = _catalog_ids(
        export_oscal_catalog(
            [_control(cid) for cid in ["ORG.BUILD", "ORG:BUILD", "org build", "ORG_BUILD", "1"]]
        )
    )
    assert alone == {"ORG.BUILD": "org-build"}
    assert crowded["ORG.BUILD"] == "org-build"
    assert all(crowded[cid] == control_token(cid) for cid in crowded)
    assert control_token("ORG:BUILD") == control_token("ORG:BUILD")
    assert control_token("ORG:BUILD").startswith("org-build-")


@pytest.mark.parametrize(
    ("first", "second"),
    [("ORG.BUILD", "ORG-BUILD"), ("ORG-BUILD", "org.build"), ("SSDF-PS.3", "ssdf-ps-3")],
)
def test_ids_that_share_a_token_fail_the_catalog_export(first: str, second: str) -> None:
    # They used to be renamed with a hash suffix, which changed the token of an
    # id already referenced as e.g. `org-build` as soon as the other was added.
    with pytest.raises(OscalControlTokenCollisionError) as raised:
        export_oscal_catalog([_control(first), _control("OTHER"), _control(second)])
    message = str(raised.value)
    assert repr(first) in message and repr(second) in message
    assert repr(control_token(first)) in message


def test_ids_that_share_a_token_fail_the_assessment_results_export() -> None:
    base = _HOSTILE["hostile-everything"]
    clash = base.control_evaluations[3].model_copy(update={"control_id": "ORG-BUILD"})
    bundle = base.model_copy(update={"control_evaluations": [*base.control_evaluations, clash]})
    with pytest.raises(OscalControlTokenCollisionError, match=r"'ORG\.BUILD' and 'ORG-BUILD'"):
        export_oscal_assessment_results(bundle)


def test_the_same_id_twice_is_not_a_collision() -> None:
    catalog = export_oscal_catalog([_control("ORG.BUILD"), _control("ORG.BUILD")])
    assert [c["id"] for g in catalog["catalog"]["groups"] for c in g["controls"]] == [
        "org-build",
        "org-build",
    ]


@pytest.mark.parametrize("name", bundled_catalog_names())
def test_bundled_catalog_tokens_keep_the_legacy_rule(name: str) -> None:
    # Every shipped id is a valid token once lower-cased with dots replaced,
    # the rule every earlier release used, so their tokens do not change and
    # no shipped catalog hits the collision error.
    controls = load_catalog(bundled_catalog_path(name))
    tokens = _catalog_ids(export_oscal_catalog(controls))
    assert tokens == {c.control_id: c.control_id.lower().replace(".", "-") for c in controls}
    assert all(_TOKEN.match(t) for t in tokens.values()), tokens


def test_bundled_catalogs_share_no_token_between_distinct_ids() -> None:
    owners: dict[str, set[str]] = {}
    for name in bundled_catalog_names():
        for control in load_catalog(bundled_catalog_path(name)):
            owners.setdefault(control_token(control.control_id), set()).add(control.control_id)
    assert {t: ids for t, ids in owners.items() if len(ids) > 1} == {}
