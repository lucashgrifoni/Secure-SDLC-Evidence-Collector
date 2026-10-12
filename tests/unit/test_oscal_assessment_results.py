"""Unit tests for the OSCAL Assessment Results exporter."""

from __future__ import annotations

import base64
import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from evidence_collector.domain.enums import (
    ConfidenceLevel,
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
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
    EvidenceSource,
    NormalizedEvidence,
    RawEvidenceRef,
    ReleaseContext,
    Summary,
)
from evidence_collector.exporters.oscal import (
    EVIDENCE_COLLECTOR_OSCAL_NS,
    export_oscal_assessment_results,
)


def _evaluation(
    control_id: str,
    status: ControlEvaluationStatus,
    *,
    criticality: ControlCriticality = ControlCriticality.HIGH,
    framework: ControlFramework = ControlFramework.NIST_SSDF,
) -> ControlEvaluation:
    return ControlEvaluation(
        control_id=control_id,
        framework=framework,
        control_name=f"{control_id} name",
        evaluation_status=status,
        criticality=criticality,
        evidence_refs=["sca-1"],
        confidence=ConfidenceLevel.HIGH,
        rationale=f"{control_id} evaluated as {status.value}",
    )


def _bundle(
    evaluations: list[ControlEvaluation],
    exceptions: list[EvidenceException] | None = None,
) -> EvidenceBundle:
    return EvidenceBundle(
        bundle_id="bundle-oscal-ar-test",
        application=Application(name="acme-api", repository="acme/api"),
        release=ReleaseContext(release_id="2026.05.18", commit_sha="abcdef1234567890"),
        evidence=[
            NormalizedEvidence(
                evidence_id="sca-1",
                evidence_type=EvidenceType.SCA_SCAN,
                source=EvidenceSource(name="trivy", kind="sarif"),
                producer="trivy",
                subject_type=SubjectType.COMMIT,
                subject_ref="abcdef1234567890",
                status=EvidenceStatus.GENERATED,
                confidence=ConfidenceLevel.HIGH,
                release_id="2026.05.18",
                commit_sha="abcdef1234567890",
            )
        ],
        control_evaluations=evaluations,
        gaps=[],
        exceptions=exceptions or [],
        summary=Summary(
            total_controls=len(evaluations),
            controls_met=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.MET
            ),
            controls_partial=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.PARTIAL
            ),
            controls_missing=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.MISSING
            ),
            controls_waived=sum(
                1 for e in evaluations if e.evaluation_status is ControlEvaluationStatus.WAIVED
            ),
            controls_not_applicable=sum(
                1
                for e in evaluations
                if e.evaluation_status is ControlEvaluationStatus.NOT_APPLICABLE
            ),
            release_status=ReleaseStatus.READY,
            evidence_coverage_score=0,
            confidence_score=0,
        ),
    )


def test_assessment_results_shape_matches_oscal_1_1_2() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    doc = export_oscal_assessment_results(bundle)

    assert "assessment-results" in doc
    ar = doc["assessment-results"]
    assert ar["metadata"]["oscal-version"] == "1.1.2"
    assert uuid.UUID(ar["uuid"])
    assert ar["results"][0]["title"].startswith("Release ")


def test_assessment_results_maps_status_to_oscal_state() -> None:
    bundle = _bundle(
        [
            _evaluation("SSDF-PW.4", ControlEvaluationStatus.MET),
            _evaluation("SSDF-PS.2", ControlEvaluationStatus.MISSING),
            _evaluation("SSDF-PW.1", ControlEvaluationStatus.PARTIAL),
        ]
    )
    findings = export_oscal_assessment_results(bundle)["assessment-results"]["results"][0][
        "findings"
    ]
    states = {f["props"][0]["value"]: f["target"]["status"]["state"] for f in findings}
    assert states["SSDF-PW.4"] == "satisfied"
    assert states["SSDF-PS.2"] == "not-satisfied"
    assert states["SSDF-PW.1"] == "not-satisfied"


def test_assessment_results_uuids_are_stable_across_runs() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    first = export_oscal_assessment_results(bundle)
    second = export_oscal_assessment_results(bundle)
    assert first["assessment-results"]["uuid"] == second["assessment-results"]["uuid"]
    assert (
        first["assessment-results"]["results"][0]["findings"][0]["uuid"]
        == second["assessment-results"]["results"][0]["findings"][0]["uuid"]
    )


def test_assessment_results_records_release_status_prop() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    props = export_oscal_assessment_results(bundle)["assessment-results"]["metadata"]["props"]
    names = {p["name"]: p["value"] for p in props}
    assert names["release_id"] == "2026.05.18"
    assert names["release_status"] == ReleaseStatus.READY.value


def test_assessment_results_emits_one_finding_per_evaluation() -> None:
    bundle = _bundle(
        [
            _evaluation("SSDF-PW.4", ControlEvaluationStatus.MET),
            _evaluation("SSDF-PS.2", ControlEvaluationStatus.MISSING),
        ]
    )
    findings = export_oscal_assessment_results(bundle)["assessment-results"]["results"][0][
        "findings"
    ]
    assert len(findings) == 2
    target_ids = sorted(f["target"]["target-id"] for f in findings)
    assert target_ids == ["ssdf-ps-2", "ssdf-pw-4"]


# ---------------------------------------------------------------------------
# WAIVED and NOT_APPLICABLE are not a clean pass. OSCAL's objective-status
# state is only `satisfied` / `not-satisfied`, so both go to `not-satisfied`
# with the reason preserved; a waiver is additionally recorded as an OSCAL
# risk with status `deviation-approved` that names the exception, matching
# the SVR exporter, which never asserts a waived control as verified.
# ---------------------------------------------------------------------------


def _waiver(exception_id: str, control_id: str) -> EvidenceException:
    return EvidenceException(
        exception_id=exception_id,
        control_id=control_id,
        approver="security-lead@acme.example",
        approved_at=datetime(2026, 5, 1, tzinfo=UTC),
        expires_at=datetime(2026, 8, 1, tzinfo=UTC),
        justification="Threat model refresh scheduled for the next quarter.",
        reference="SEC-1234",
    )


def _results(doc: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = doc["assessment-results"]["results"][0]
    return result


def _finding(doc: dict[str, Any], control_id: str) -> dict[str, Any]:
    return next(
        f
        for f in _results(doc)["findings"]
        if {"name": "control_id", "value": control_id} in f["props"]
    )


def test_waived_control_is_not_satisfied_and_records_the_waiver() -> None:
    waived = _evaluation("SSDF-PW.1", ControlEvaluationStatus.WAIVED).model_copy(
        update={"exception_refs": ["EXC-7"]}
    )
    bundle = _bundle([waived], [_waiver("EXC-7", "SSDF-PW.1")])
    doc = export_oscal_assessment_results(bundle)
    finding = _finding(doc, "SSDF-PW.1")

    assert finding["target"]["status"]["state"] == "not-satisfied"
    assert {"name": "exception_id", "value": "EXC-7"} in finding["props"]
    assert {"name": "not_satisfied_reason", "value": "waived"} in finding["props"]

    risks = {r["uuid"]: r for r in _results(doc)["risks"]}
    related = [r["risk-uuid"] for r in finding["related-risks"]]
    assert len(related) == 1
    risk = risks[related[0]]
    assert risk["status"] == "deviation-approved"
    assert {"name": "exception_id", "value": "EXC-7"} in risk["props"]
    assert risk["deadline"].startswith("2026-08-01T00:00:00")
    assert "Threat model refresh" in risk["description"]


def test_not_applicable_control_is_not_satisfied_without_a_risk() -> None:
    bundle = _bundle([_evaluation("SSDF-PW.9", ControlEvaluationStatus.NOT_APPLICABLE)])
    doc = export_oscal_assessment_results(bundle)
    finding = _finding(doc, "SSDF-PW.9")
    assert finding["target"]["status"]["state"] == "not-satisfied"
    assert {"name": "not_satisfied_reason", "value": "not_applicable"} in finding["props"]
    assert "related-risks" not in finding
    assert "risks" not in _results(doc)


def test_met_control_carries_no_risk_or_reason() -> None:
    doc = export_oscal_assessment_results(
        _bundle([_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET)])
    )
    finding = _finding(doc, "SSDF-PW.4")
    assert finding["target"]["status"]["state"] == "satisfied"
    assert "related-risks" not in finding
    assert all(p["name"] != "not_satisfied_reason" for p in finding["props"])
    assert "risks" not in _results(doc)


def _all_uuids(node: Any, key: str = "uuid") -> set[str]:
    """Every value stored under ``key`` anywhere in ``node``."""
    found: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key and isinstance(v, str):
                found.add(v)
            found |= _all_uuids(v, key)
    elif isinstance(node, list):
        for item in node:
            found |= _all_uuids(item, key)
    return found


def _waived_bundle(application: str, repository: str) -> EvidenceBundle:
    waived = _evaluation("SSDF-PW.1", ControlEvaluationStatus.WAIVED).model_copy(
        update={"exception_refs": ["EXC-7"]}
    )
    bundle = _bundle(
        [_evaluation("SSDF-PW.4", ControlEvaluationStatus.MET), waived],
        [_waiver("EXC-7", "SSDF-PW.1")],
    )
    return bundle.model_copy(
        update={"application": Application(name=application, repository=repository)}
    )


def test_uuids_do_not_collide_across_applications_sharing_a_release_id() -> None:
    # Two services cut on the same calendar release id are two OSCAL subjects.
    # A GRC store keyed on uuid used to merge one service's findings into the
    # other's, because only the release id and control id seeded the uuids.
    billing = export_oscal_assessment_results(_waived_bundle("billing-api", "acme/billing-api"))
    payments = export_oscal_assessment_results(_waived_bundle("payments-api", "acme/payments-api"))

    assert _all_uuids(billing).isdisjoint(_all_uuids(payments))


def test_uuids_differ_for_the_same_application_name_in_another_repository() -> None:
    first = export_oscal_assessment_results(_waived_bundle("api", "acme/api"))
    second = export_oscal_assessment_results(_waived_bundle("api", "other-org/api"))

    assert _all_uuids(first).isdisjoint(_all_uuids(second))


def test_uuids_differ_per_environment_and_metadata_names_it() -> None:
    # The same release assessed in staging and in production is two subjects.
    staging_bundle = _waived_bundle("api", "acme/api")
    staging_bundle = staging_bundle.model_copy(
        update={
            "application": staging_bundle.application.model_copy(update={"environment": "staging"})
        }
    )
    staging = export_oscal_assessment_results(staging_bundle)
    production = export_oscal_assessment_results(_waived_bundle("api", "acme/api"))

    assert _all_uuids(staging).isdisjoint(_all_uuids(production))
    props = {p["name"]: p["value"] for p in staging["assessment-results"]["metadata"]["props"]}
    assert props["environment"] == "staging"
    _, plan = _embedded_assessment_plan(staging)
    plan_props = {p["name"]: p["value"] for p in plan["assessment-plan"]["metadata"]["props"]}
    assert plan_props["environment"] == "staging"


def test_every_internal_reference_resolves_inside_the_document() -> None:
    doc = export_oscal_assessment_results(_waived_bundle("acme-api", "acme/api"))
    ar = doc["assessment-results"]
    result = ar["results"][0]
    observation_uuids = {o["uuid"] for o in result["observations"]}
    risk_uuids = {r["uuid"] for r in result["risks"]}
    resource_uuids = {r["uuid"] for r in ar["back-matter"]["resources"]}

    assert _all_uuids(doc, "observation-uuid") <= observation_uuids
    assert _all_uuids(doc, "risk-uuid") <= risk_uuids
    # No reference may point at a uuid the document does not define.
    assert _all_uuids(doc, "subject-uuid") == set()

    fragments = {href[1:] for href in _all_uuids(doc, "href") if href.startswith("#")}
    assert ar["import-ap"]["href"].startswith("#")
    assert fragments, "import-ap and the evidence links are fragment references"
    assert fragments <= resource_uuids


def test_observation_links_each_evidence_ref_to_a_back_matter_resource() -> None:
    doc = export_oscal_assessment_results(_waived_bundle("acme-api", "acme/api"))
    ar = doc["assessment-results"]
    resources = {r["uuid"]: r for r in ar["back-matter"]["resources"]}
    observation = ar["results"][0]["observations"][0]

    links = observation["relevant-evidence"]
    assert len(links) == 1
    resource = resources[links[0]["href"][1:]]
    assert {"name": "evidence_id", "value": "sca-1"} in resource["props"]
    assert links[0]["description"]


def _embedded_assessment_plan(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (import-ap resource, decoded assessment-plan document)."""
    ar = doc["assessment-results"]
    target = ar["import-ap"]["href"]
    assert target.startswith("#")
    resource = next(r for r in ar["back-matter"]["resources"] if r["uuid"] == target[1:])
    encoded = resource["base64"]
    assert encoded["media-type"] == "application/oscal+json"
    plan = json.loads(base64.b64decode(encoded["value"]).decode("utf-8"))
    return resource, plan


def test_import_ap_resolves_to_an_embedded_assessment_plan_document() -> None:
    # import-ap used to point at a back-matter resource carrying only a title
    # and a description: something that resolved, but not an assessment plan.
    bundle = _waived_bundle("acme-api", "acme/api")
    doc = export_oscal_assessment_results(bundle)
    _resource, plan = _embedded_assessment_plan(doc)

    ap = plan["assessment-plan"]
    assert uuid.UUID(ap["uuid"])
    for key in ("title", "last-modified", "version", "oscal-version"):
        assert ap["metadata"][key]
    assert ap["metadata"]["oscal-version"] == "1.1.2"
    assert ap["import-ssp"]["href"].startswith("#")
    ssp_target = ap["import-ssp"]["href"][1:]
    assert ssp_target in {r["uuid"] for r in ap["back-matter"]["resources"]}

    selected = ap["reviewed-controls"]["control-selections"][0]["include-controls"]
    assert [c["control-id"] for c in selected] == ["ssdf-pw-4", "ssdf-pw-1"]


def test_embedded_assessment_plan_is_stable_and_scoped_to_the_application() -> None:
    first = _embedded_assessment_plan(
        export_oscal_assessment_results(_waived_bundle("billing-api", "acme/billing-api"))
    )[1]
    again = _embedded_assessment_plan(
        export_oscal_assessment_results(_waived_bundle("billing-api", "acme/billing-api"))
    )[1]
    other = _embedded_assessment_plan(
        export_oscal_assessment_results(_waived_bundle("payments-api", "acme/payments-api"))
    )[1]

    assert first == again
    assert first["assessment-plan"]["uuid"] != other["assessment-plan"]["uuid"]


def _resources_without_content(resources: list[dict[str, Any]]) -> list[str]:
    return [r["uuid"] for r in resources if not r.get("rlinks") and "base64" not in r]


def test_every_back_matter_resource_carries_an_rlink_or_base64() -> None:
    # OSCAL 1.1.2 requires each back-matter resource to hold at least one
    # rlink or a base64 payload; metadata alone does not make a resource.
    doc = export_oscal_assessment_results(_with_recorded_artifact(_waived_bundle("a", "o/a")))
    _resource, plan = _embedded_assessment_plan(doc)

    assert _resources_without_content(doc["assessment-results"]["back-matter"]["resources"]) == []
    assert _resources_without_content(plan["assessment-plan"]["back-matter"]["resources"]) == []


def _with_recorded_artifact(
    bundle: EvidenceBundle,
    artifact_path: str | None = "artifacts/trivy report.sarif",
    artifact_uri: str | None = None,
) -> EvidenceBundle:
    item = bundle.evidence[0].model_copy(
        update={
            "raw": RawEvidenceRef(
                artifact_path=artifact_path,
                artifact_uri=artifact_uri,
                integrity_hash="sha256:" + "ab" * 32,
                content_type="application/sarif+json",
            )
        }
    )
    return bundle.model_copy(update={"evidence": [item]})


def _evidence_resource(doc: dict[str, Any], evidence_id: str) -> dict[str, Any]:
    return next(
        r
        for r in doc["assessment-results"]["back-matter"]["resources"]
        if {"name": "evidence_id", "value": evidence_id} in r.get("props", [])
    )


@pytest.mark.parametrize(
    ("artifact_path", "artifact_uri", "href"),
    [
        ("/srv/ci/trivy report.sarif", None, "file:///srv/ci/trivy%20report.sarif"),
        ("C:\\ci\\trivy.sarif", None, "file:///C:/ci/trivy.sarif"),
        ("\\\\server\\share\\trivy.sarif", None, "file://server/share/trivy.sarif"),
        (None, "https://ci.example/run/7/trivy.sarif", "https://ci.example/run/7/trivy.sarif"),
    ],
)
def test_evidence_resource_links_only_to_an_absolute_location(
    artifact_path: str | None, artifact_uri: str | None, href: str
) -> None:
    bundle = _with_recorded_artifact(_waived_bundle("a", "o/a"), artifact_path, artifact_uri)
    resource = _evidence_resource(export_oscal_assessment_results(bundle), "sca-1")
    rlink = resource["rlinks"][0]

    assert "base64" not in resource
    assert rlink["href"] == href
    assert rlink["media-type"] == "application/sarif+json"
    assert rlink["hashes"] == [{"algorithm": "SHA-256", "value": "ab" * 32}]


@pytest.mark.parametrize(
    "integrity_hash",
    ["sha256:", "sha256:" + "zz" * 32, "sha256:" + "ab" * 31, "md5:" + "ab" * 16],
    ids=["empty", "not-hex", "too-short", "other-algorithm"],
)
def test_evidence_resource_omits_a_hash_that_is_not_a_full_sha256(integrity_hash: str) -> None:
    bundle = _with_recorded_artifact(_waived_bundle("a", "o/a"), "/srv/ci/trivy.sarif")
    item = bundle.evidence[0]
    assert item.raw is not None
    raw = item.raw.model_copy(update={"integrity_hash": integrity_hash})
    bundle = bundle.model_copy(update={"evidence": [item.model_copy(update={"raw": raw})]})
    rlink = _evidence_resource(export_oscal_assessment_results(bundle), "sca-1")["rlinks"][0]

    assert "hashes" not in rlink


@pytest.mark.parametrize(
    "artifact_path",
    [
        "artifacts/trivy report.sarif",
        "reports\\scan.json",
        # Drive-relative: has a drive but no root, and as_uri() rejects it.
        "C:reports\\scan.json",
    ],
)
def test_a_relative_artifact_path_is_recorded_as_a_prop_not_a_link(artifact_path: str) -> None:
    # A relative path is relative to the collection root, but OSCAL resolves a
    # relative rlink against the AR document, so a link would point elsewhere.
    bundle = _with_recorded_artifact(_waived_bundle("a", "o/a"), artifact_path)
    resource = _evidence_resource(export_oscal_assessment_results(bundle), "sca-1")

    assert "rlinks" not in resource
    record = json.loads(base64.b64decode(resource["base64"]["value"]).decode("utf-8"))
    assert record["evidence_id"] == "sca-1"
    assert {
        "name": "artifact-path",
        "ns": EVIDENCE_COLLECTOR_OSCAL_NS,
        "value": artifact_path,
    } in resource["props"]


@pytest.mark.parametrize("evidence_id", ["scan:1", "scan/1", "1", "ok-id"])
def test_base64_filename_is_a_valid_ncname(evidence_id: str) -> None:
    bundle = _waived_bundle("a", "o/a")
    item = bundle.evidence[0].model_copy(update={"evidence_id": evidence_id})
    evaluations = [
        ev.model_copy(update={"evidence_refs": [evidence_id]}) for ev in bundle.control_evaluations
    ]
    bundle = bundle.model_copy(update={"evidence": [item], "control_evaluations": evaluations})
    resource = _evidence_resource(export_oscal_assessment_results(bundle), evidence_id)

    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]*", resource["base64"]["filename"])


def test_evidence_resource_without_a_path_embeds_the_normalized_record() -> None:
    doc = export_oscal_assessment_results(_waived_bundle("a", "o/a"))
    encoded = _evidence_resource(doc, "sca-1")["base64"]

    assert encoded["media-type"] == "application/json"
    record = json.loads(base64.b64decode(encoded["value"]).decode("utf-8"))
    assert record["evidence_id"] == "sca-1"
    assert record["evidence_type"] == "sca_scan"


def test_ssp_placeholder_carries_its_statement_as_base64() -> None:
    _resource, plan = _embedded_assessment_plan(
        export_oscal_assessment_results(_waived_bundle("acme-api", "acme/api"))
    )
    ap = plan["assessment-plan"]
    target = ap["import-ssp"]["href"][1:]
    placeholder = next(r for r in ap["back-matter"]["resources"] if r["uuid"] == target)

    assert placeholder["base64"]["media-type"] == "text/plain"
    text = base64.b64decode(placeholder["base64"]["value"]).decode("utf-8")
    assert "No OSCAL system security plan is published" in text
    assert "acme-api" in text


@pytest.mark.parametrize(
    "artifact_uri",
    ["https://example.test/%zz", "https://example.test/50%", "https://example.test/%4"],
    ids=["non-hex-escape", "bare-percent", "short-escape"],
)
def test_evidence_resource_does_not_link_a_uri_with_a_malformed_percent_escape(
    artifact_uri: str,
) -> None:
    bundle = _with_recorded_artifact(_waived_bundle("a", "o/a"), None, artifact_uri)
    resource = _evidence_resource(export_oscal_assessment_results(bundle), "sca-1")

    assert "rlinks" not in resource
    assert "base64" in resource


def test_evidence_resource_links_a_uri_with_valid_percent_escapes() -> None:
    uri = "https://example.test/trivy%20report.sarif"
    bundle = _with_recorded_artifact(_waived_bundle("a", "o/a"), None, uri)
    resource = _evidence_resource(export_oscal_assessment_results(bundle), "sca-1")

    assert resource["rlinks"][0]["href"] == uri
