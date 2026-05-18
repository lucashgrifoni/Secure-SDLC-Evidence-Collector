"""OSCAL Catalog + Assessment Results exporter.

Auditors and government compliance frameworks (FedRAMP, HITRUST,
StateRAMP, OSCAL-aware GRC tools) speak NIST OSCAL natively. This
exporter renders the project's control catalog as an OSCAL Catalog
Model JSON document conformant with the OSCAL 1.1.x schema and the
per-release control evaluations as an OSCAL Assessment Results (AR)
Model document.

The AR exporter is the closing leg of the FedRAMP 20x story: by
2026-09 every CSP must submit machine-readable AR packages alongside
the SSP. This module emits the AR model that fits that contract.

References

* OSCAL Catalog Model — https://pages.nist.gov/OSCAL/learn/concepts/layer/control/catalog/
* OSCAL Assessment Results Model — https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
* FedRAMP 20x machine-readable packages — https://www.workstreet.com/blog/fedramp-20x-requirements
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
_OSCAL_TARGET_STATE: dict[ControlEvaluationStatus, str] = {
    ControlEvaluationStatus.MET: "satisfied",
    ControlEvaluationStatus.PARTIAL: "not-satisfied",
    ControlEvaluationStatus.MISSING: "not-satisfied",
    ControlEvaluationStatus.WAIVED: "satisfied",
    ControlEvaluationStatus.NOT_APPLICABLE: "satisfied",
}


def _evaluation_uuid(release_id: str, control_id: str) -> str:
    """Stable UUIDv5 for an (release_id, control_id) finding."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"eval:{release_id}:{control_id}"))


def _observation_uuid(release_id: str, control_id: str) -> str:
    """Stable UUIDv5 for the observation that backs a finding."""
    return str(uuid.uuid5(_OSCAL_NAMESPACE, f"obs:{release_id}:{control_id}"))


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
    return {
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
        "props": [
            {"name": "control_id", "value": evaluation.control_id},
            {"name": "evaluation_status", "value": evaluation.evaluation_status.value},
            {"name": "criticality", "value": evaluation.criticality.value},
        ],
    }


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

    return {
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
