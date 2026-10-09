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


def _evaluation_uuid(release_id: str, control_id: str) -> str:
    """Stable UUIDv5 for an (release_id, control_id) finding."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"eval:{release_id}:{control_id}"))


def _observation_uuid(release_id: str, control_id: str) -> str:
    """Stable UUIDv5 for the observation that backs a finding."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"obs:{release_id}:{control_id}"))


def _risk_uuid(release_id: str, control_id: str) -> str:
    """Stable UUIDv5 for the approved-deviation risk of a waived control."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"risk:{release_id}:{control_id}"))


def _result_uuid(release_id: str) -> str:
    """Stable UUIDv5 for the single assessment result this AR carries."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"result:{release_id}"))


def _ar_uuid(release_id: str, commit_sha: str) -> str:
    """Stable UUIDv5 for the top-level assessment-results document."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"ar:{release_id}:{commit_sha}"))


def _control_target_id(control_id: str) -> str:
    """OSCAL control id, kebab-case, lower."""
    return control_id.lower().replace(".", "-")


def _evaluation_to_observation(
    evaluation: ControlEvaluation,
    release_id: str,
    collected_iso: str,
) -> dict[str, Any]:
    return {
        "uuid": _observation_uuid(release_id, evaluation.control_id),
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
        "subjects": [
            {"subject-uuid": _observation_uuid(release_id, ref), "type": "evidence"}
            for ref in evaluation.evidence_refs
        ],
    }


def _evaluation_to_finding(
    evaluation: ControlEvaluation,
    release_id: str,
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
        "uuid": _evaluation_uuid(release_id, evaluation.control_id),
        "title": evaluation.control_name,
        "description": evaluation.rationale,
        "target": {
            "type": "objective-id",
            "target-id": _control_target_id(evaluation.control_id),
            "status": {"state": state},
        },
        "related-observations": [
            {"observation-uuid": _observation_uuid(release_id, evaluation.control_id)}
        ],
        "props": props,
    }
    if evaluation.evaluation_status is ControlEvaluationStatus.WAIVED:
        finding["related-risks"] = [{"risk-uuid": _risk_uuid(release_id, evaluation.control_id)}]
    return finding


def _waiver_to_risk(
    evaluation: ControlEvaluation,
    release_id: str,
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
        "uuid": _risk_uuid(release_id, evaluation.control_id),
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
    collected_iso = (bundle.generated_at or datetime.now(tz=UTC)).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )

    observations = [
        _evaluation_to_observation(ev, release_id, collected_iso)
        for ev in bundle.control_evaluations
    ]
    findings = [_evaluation_to_finding(ev, release_id) for ev in bundle.control_evaluations]
    exceptions = {exc.exception_id: exc for exc in bundle.exceptions}
    risks = [
        _waiver_to_risk(ev, release_id, exceptions)
        for ev in bundle.control_evaluations
        if ev.evaluation_status is ControlEvaluationStatus.WAIVED
    ]

    document: dict[str, Any] = {
        "assessment-results": {
            "uuid": _ar_uuid(release_id, commit_sha),
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
            "import-ap": {"href": "#sdlc-evidence-assessment-plan"},
            "results": [
                {
                    "uuid": _result_uuid(release_id),
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
    return document
