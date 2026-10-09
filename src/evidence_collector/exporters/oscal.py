"""OSCAL Catalog + Assessment Results exporter.

Auditors and government compliance frameworks (FedRAMP, HITRUST,
StateRAMP, OSCAL-aware GRC tools) speak NIST OSCAL natively. This
exporter renders the project's control catalog as an OSCAL Catalog
Model JSON document conformant with the OSCAL 1.1.x schema and the
per-release control evaluations as an OSCAL Assessment Results (AR)
Model document.

FedRAMP CR26 asks providers for machine-readable JSON that validates
against FedRAMP JSON schemas (FRC-CSO-JSN). This module emits OSCAL AR
documents; it does not produce or validate a FedRAMP schema package.

References

* OSCAL Catalog Model — https://pages.nist.gov/OSCAL/learn/concepts/layer/control/catalog/
* OSCAL Assessment Results Model — https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
* FedRAMP CR26 rules 2026.10.05.01 — https://github.com/FedRAMP/rules/blob/1c33385a06acf4faf50da2b9b4dc31cd826e5b91/fedramp-consolidated-rules.json
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from evidence_collector import __version__
from evidence_collector.domain.enums import (
    ControlCriticality,
    ControlEvaluationStatus,
    ControlFramework,
)
from evidence_collector.domain.models import (
    ControlDefinition,
    ControlEvaluation,
    EvidenceBundle,
    EvidenceException,
)

# Stable, project-scoped namespace for synthesizing OSCAL UUIDs from
# control IDs. Generated once and frozen so the same control_id always
# maps to the same OSCAL uuid across runs (required for stable diffs).
_OSCAL_NAMESPACE = uuid.UUID("c5f8d34a-2c4b-4f8c-9e07-21f1f9e2a4c1")


def _control_uuid(control_id: str) -> str:
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"control:{control_id}"))


def _group_for_framework(framework: ControlFramework) -> str:
    # OSCAL groups controls by framework so consumers can filter at
    # ingestion. Use stable, kebab-case identifiers.
    mapping = {
        ControlFramework.NIST_SSDF: "nist-ssdf",
        ControlFramework.OWASP_SAMM: "owasp-samm",
        ControlFramework.ORG_INTERNAL: "org-internal",
    }
    return mapping.get(framework, "uncategorized")


def _criticality_to_class(criticality: ControlCriticality) -> str:
    # Encode criticality as an OSCAL `class` rather than a custom
    # property so policy filters in OSCAL-native tooling can use it.
    return f"criticality-{criticality.value}"


def _control_to_oscal(control: ControlDefinition) -> dict[str, Any]:
    properties = [
        {"name": "control_id", "value": control.control_id},
        {"name": "framework", "value": control.framework.value},
        {"name": "criticality", "value": control.criticality.value},
    ]
    if control.required_evidence_types:
        properties.append(
            {
                "name": "required_evidence_types",
                "value": ",".join(sorted(t.value for t in control.required_evidence_types)),
            }
        )
    if control.recommended_evidence_types:
        properties.append(
            {
                "name": "recommended_evidence_types",
                "value": ",".join(sorted(t.value for t in control.recommended_evidence_types)),
            }
        )
    parts: list[dict[str, Any]] = [
        {"name": "statement", "prose": control.description},
    ]
    if control.rationale_template:
        parts.append({"name": "guidance", "prose": control.rationale_template})

    return {
        "id": control.control_id.lower().replace(".", "-"),
        "uuid": _control_uuid(control.control_id),
        "class": _criticality_to_class(control.criticality),
        "title": control.name,
        "props": properties,
        "parts": parts,
    }


def export_oscal_catalog(controls: Iterable[ControlDefinition]) -> dict[str, Any]:
    """Render the catalog as a single OSCAL Catalog JSON document."""
    controls_list = list(controls)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for control in controls_list:
        grouped.setdefault(_group_for_framework(control.framework), []).append(
            _control_to_oscal(control)
        )

    groups = [
        {
            "id": group_id,
            "title": group_id.replace("-", " ").title(),
            "controls": grouped[group_id],
        }
        for group_id in sorted(grouped)
    ]

    catalog_uuid = str(uuid.uuid5(_OSCAL_NAMESPACE, "catalog:secure-sdlc-evidence-collector"))
    last_modified = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

    return {
        "catalog": {
            "uuid": catalog_uuid,
            "metadata": {
                "title": "Secure SDLC Evidence Collector — control catalog",
                "last-modified": last_modified,
                "version": __version__,
                "oscal-version": "1.1.2",
                "props": [
                    {
                        "name": "source",
                        "value": "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector",
                    }
                ],
            },
            "groups": groups,
        }
    }


# ---------------------------------------------------------------------------
# OSCAL Assessment Results (AR) exporter
# ---------------------------------------------------------------------------

# Map our internal `ControlEvaluationStatus` onto OSCAL's
# `assessment-results.results[].findings[].target.status.state` vocabulary.
# OSCAL only defines `satisfied` and `not-satisfied`; everything that is
# not a clean pass goes to `not-satisfied` with the original status
# preserved as a property for downstream consumers.
#
# WAIVED and NOT_APPLICABLE are not a clean pass: the objective was not
# shown to be met. Both used to map to `satisfied`, so an OSCAL consumer read
# a waived control as a demonstrated one, while the SVR exporter deliberately
# leaves waived and not-applicable controls out of what it asserts. They now
# go to `not-satisfied`, named by a `not_satisfied_reason` property; a waiver
# is also recorded as an OSCAL risk with status `deviation-approved` that
# names the exception, which is how OSCAL expresses an accepted deviation.
_OSCAL_TARGET_STATE: dict[ControlEvaluationStatus, str] = {
    ControlEvaluationStatus.MET: "satisfied",
    ControlEvaluationStatus.PARTIAL: "not-satisfied",
    ControlEvaluationStatus.MISSING: "not-satisfied",
    ControlEvaluationStatus.WAIVED: "not-satisfied",
    ControlEvaluationStatus.NOT_APPLICABLE: "not-satisfied",
}

# Statuses whose `not-satisfied` state means "not asserted" rather than "the
# evidence fell short", recorded so a consumer can tell the two apart.
_NOT_SATISFIED_REASON: dict[ControlEvaluationStatus, str] = {
    ControlEvaluationStatus.WAIVED: "waived",
    ControlEvaluationStatus.NOT_APPLICABLE: "not_applicable",
}

_OSCAL_DATETIME = "%Y-%m-%dT%H:%M:%S.000+00:00"


def _assessment_scope(bundle: EvidenceBundle) -> str:
    """The subject every per-release uuid is scoped to.

    OSCAL finding, observation and result uuids are globally unique and
    assigned per subject. Two applications cut on the same release id (a
    calendar tag such as ``2026.04.10`` is common across an org) are two
    subjects, so the application name, its repository and the release id all
    seed the uuid. JSON keeps the parts unambiguous whatever they contain.
    """
    return json.dumps(
        [bundle.application.name, bundle.application.repository, bundle.release.release_id],
        ensure_ascii=False,
    )


def _scoped_uuid(kind: str, scope: str, *parts: str) -> str:
    return str(uuid.uuid5(_OSCAL_NAMESPACE, ":".join((kind, scope, *parts))))


def _evaluation_uuid(scope: str, control_id: str) -> str:
    """Stable UUIDv5 for the finding of one control in one subject's release."""
    return _scoped_uuid("eval", scope, control_id)


def _observation_uuid(scope: str, control_id: str) -> str:
    """Stable UUIDv5 for the observation that backs a finding."""
    return _scoped_uuid("obs", scope, control_id)


def _risk_uuid(scope: str, control_id: str) -> str:
    """Stable UUIDv5 for the approved-deviation risk of a waived control."""
    return _scoped_uuid("risk", scope, control_id)


def _evidence_resource_uuid(scope: str, evidence_id: str) -> str:
    """Stable UUIDv5 for the back-matter resource describing one evidence item."""
    return _scoped_uuid("evidence", scope, evidence_id)


def _assessment_plan_resource_uuid(scope: str) -> str:
    """Stable UUIDv5 for the back-matter resource ``import-ap`` points at."""
    return _scoped_uuid("ap", scope)


def _result_uuid(scope: str) -> str:
    """Stable UUIDv5 for the single assessment result this AR carries."""
    return _scoped_uuid("result", scope)


def _ar_uuid(scope: str, commit_sha: str) -> str:
    """Stable UUIDv5 for the top-level assessment-results document."""
    return _scoped_uuid("ar", scope, commit_sha)


def _control_target_id(control_id: str) -> str:
    """OSCAL control id, kebab-case, lower."""
    return control_id.lower().replace(".", "-")


def _evaluation_to_observation(
    evaluation: ControlEvaluation,
    scope: str,
    collected_iso: str,
) -> dict[str, Any]:
    # Each evidence ref links to a back-matter resource in this document. The
    # refs used to be hashed into `subjects[].subject-uuid` values that matched
    # nothing, so the evidence behind a finding could not be recovered.
    return {
        "uuid": _observation_uuid(scope, evaluation.control_id),
        "title": f"Evidence for {evaluation.control_id}",
        "description": evaluation.rationale,
        "methods": ["EXAMINE"],
        "types": ["evidence"],
        "collected": collected_iso,
        "props": [
            {"name": "control_id", "value": evaluation.control_id},
            {"name": "framework", "value": evaluation.framework.value},
            {"name": "criticality", "value": evaluation.criticality.value},
            {"name": "evaluation_status", "value": evaluation.evaluation_status.value},
            {"name": "confidence", "value": evaluation.confidence.value},
        ],
        "relevant-evidence": [
            {
                "href": f"#{_evidence_resource_uuid(scope, ref)}",
                "description": f"Evidence item {ref}",
            }
            for ref in evaluation.evidence_refs
        ],
    }


def _evaluation_to_finding(
    evaluation: ControlEvaluation,
    scope: str,
) -> dict[str, Any]:
    state = _OSCAL_TARGET_STATE.get(evaluation.evaluation_status, "not-satisfied")
    props = [
        {"name": "control_id", "value": evaluation.control_id},
        {"name": "evaluation_status", "value": evaluation.evaluation_status.value},
        {"name": "criticality", "value": evaluation.criticality.value},
    ]
    reason = _NOT_SATISFIED_REASON.get(evaluation.evaluation_status)
    if reason is not None:
        props.append({"name": "not_satisfied_reason", "value": reason})
    props.extend({"name": "exception_id", "value": ref} for ref in evaluation.exception_refs)
    finding: dict[str, Any] = {
        "uuid": _evaluation_uuid(scope, evaluation.control_id),
        "title": evaluation.control_name,
        "description": evaluation.rationale,
        "target": {
            "type": "objective-id",
            "target-id": _control_target_id(evaluation.control_id),
            "status": {"state": state},
        },
        "related-observations": [
            {"observation-uuid": _observation_uuid(scope, evaluation.control_id)}
        ],
        "props": props,
    }
    if evaluation.evaluation_status is ControlEvaluationStatus.WAIVED:
        finding["related-risks"] = [{"risk-uuid": _risk_uuid(scope, evaluation.control_id)}]
    return finding


def _waiver_to_risk(
    evaluation: ControlEvaluation,
    scope: str,
    exceptions: dict[str, EvidenceException],
) -> dict[str, Any]:
    """Record a waived control as an OSCAL risk with an approved deviation.

    The exception ids come from the evaluation; the justification, approver,
    reference and expiry are added for each id the bundle also carries.
    """
    waivers = [exceptions[ref] for ref in evaluation.exception_refs if ref in exceptions]
    ids = ", ".join(evaluation.exception_refs) or "an unnamed exception"
    props: list[dict[str, str]] = [{"name": "control_id", "value": evaluation.control_id}]
    props.extend({"name": "exception_id", "value": ref} for ref in evaluation.exception_refs)
    props.extend({"name": "approver", "value": w.approver} for w in waivers)
    props.extend({"name": "reference", "value": w.reference} for w in waivers if w.reference)
    risk: dict[str, Any] = {
        "uuid": _risk_uuid(scope, evaluation.control_id),
        "title": f"Approved deviation for {evaluation.control_id}",
        "description": " ".join(w.justification for w in waivers) or f"Control waived by {ids}.",
        "statement": (
            f"Control {evaluation.control_id} was waived by {ids}; its required "
            "evidence was not demonstrated for this release."
        ),
        "status": "deviation-approved",
        "props": props,
    }
    if waivers:
        earliest = min(w.expires_at for w in waivers).astimezone(UTC)
        risk["deadline"] = earliest.strftime(_OSCAL_DATETIME)
    return risk


def export_oscal_assessment_results(bundle: EvidenceBundle) -> dict[str, Any]:
    """Render the bundle's control evaluations as an OSCAL AR JSON document.

    The output is a single ``assessment-results`` document with one
    ``results`` entry: the per-release control evaluations of this
    bundle become OSCAL findings + observations linked through stable
    UUIDv5 ids so re-running the export on the same inputs yields the
    same uuids (required for diff-friendly compliance pipelines).
    """
    release_id = bundle.release.release_id
    commit_sha = bundle.release.commit_sha
    scope = _assessment_scope(bundle)
    collected_iso = (bundle.generated_at or datetime.now(tz=UTC)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )

    observations = [
        _evaluation_to_observation(ev, scope, collected_iso) for ev in bundle.control_evaluations
    ]
    findings = [_evaluation_to_finding(ev, scope) for ev in bundle.control_evaluations]
    exceptions = {exc.exception_id: exc for exc in bundle.exceptions}
    risks = [
        _waiver_to_risk(ev, scope, exceptions)
        for ev in bundle.control_evaluations
        if ev.evaluation_status is ControlEvaluationStatus.WAIVED
    ]

    document: dict[str, Any] = {
        "assessment-results": {
            "uuid": _ar_uuid(scope, commit_sha),
            "metadata": {
                "title": (f"Assessment Results · {bundle.application.name} · release {release_id}"),
                "last-modified": collected_iso,
                "version": __version__,
                "oscal-version": "1.1.2",
                "props": [
                    {"name": "source", "value": "secure-sdlc-evidence-collector"},
                    {"name": "release_id", "value": release_id},
                    {"name": "commit_sha", "value": commit_sha},
                    {
                        "name": "release_status",
                        "value": bundle.summary.release_status.value,
                    },
                ],
            },
            "import-ap": {"href": f"#{_assessment_plan_resource_uuid(scope)}"},
            "results": [
                {
                    "uuid": _result_uuid(scope),
                    "title": f"Release {release_id}",
                    "description": (
                        f"Secure SDLC evidence evaluation for "
                        f"{bundle.application.name}@{release_id} "
                        f"({commit_sha[:12]})"
                    ),
                    "start": collected_iso,
                    "end": collected_iso,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": "Controls evaluated by this assessment",
                                "include-controls": [
                                    {"control-id": _control_target_id(ev.control_id)}
                                    for ev in bundle.control_evaluations
                                ],
                            }
                        ],
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }
    if risks:
        document["assessment-results"]["results"][0]["risks"] = risks
    document["assessment-results"]["back-matter"] = {
        "resources": [
            _assessment_plan_resource(bundle, scope),
            *_evidence_resources(bundle, scope),
        ]
    }
    return document


def _assessment_plan_resource(bundle: EvidenceBundle, scope: str) -> dict[str, Any]:
    """The resource ``import-ap`` resolves to.

    OSCAL requires ``import-ap``, but the collector publishes no separate
    assessment plan: the plan is the control catalog the bundle was evaluated
    against. The fragment used to name a resource the document never defined.
    """
    props: list[dict[str, str]] = []
    if bundle.catalog is not None:
        props = [
            {"name": "catalog_origin", "value": bundle.catalog.origin},
            {"name": "catalog_name", "value": bundle.catalog.name},
            {"name": "catalog_sha256", "value": bundle.catalog.sha256},
        ]
    resource: dict[str, Any] = {
        "uuid": _assessment_plan_resource_uuid(scope),
        "title": "Assessment plan",
        "description": (
            "No separate OSCAL assessment plan is published. Each control was "
            "evaluated against the control catalog recorded in the evidence bundle."
        ),
    }
    if props:
        resource["props"] = props
    return resource


def _evidence_resources(bundle: EvidenceBundle, scope: str) -> list[dict[str, Any]]:
    """One back-matter resource per evidence id any observation links to."""
    by_id = {item.evidence_id: item for item in bundle.evidence}
    referenced = sorted({ref for ev in bundle.control_evaluations for ref in ev.evidence_refs})
    resources: list[dict[str, Any]] = []
    for evidence_id in referenced:
        props = [{"name": "evidence_id", "value": evidence_id}]
        item = by_id.get(evidence_id)
        if item is None:
            description = "Evidence item named by an evaluation but absent from the bundle."
        else:
            description = f"{item.evidence_type.value} evidence produced by {item.producer}."
            props.append({"name": "evidence_type", "value": item.evidence_type.value})
            props.append({"name": "evidence_status", "value": item.status.value})
            if item.raw is not None and item.raw.integrity_hash:
                props.append({"name": "integrity_hash", "value": item.raw.integrity_hash})
        resources.append(
            {
                "uuid": _evidence_resource_uuid(scope, evidence_id),
                "title": evidence_id,
                "description": description,
                "props": props,
            }
        )
    return resources
