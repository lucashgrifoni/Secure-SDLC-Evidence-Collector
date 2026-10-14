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

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath
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
    NormalizedEvidence,
    RawEvidenceRef,
)
from evidence_collector.exporters._uri import is_absolute_uri

# Stable, project-scoped namespace for synthesizing OSCAL UUIDs from
# control IDs. Generated once and frozen so the same control_id always
# maps to the same OSCAL uuid across runs (required for stable diffs).
_OSCAL_NAMESPACE = uuid.UUID("c5f8d34a-2c4b-4f8c-9e07-21f1f9e2a4c1")

# `ns` for props this project defines that OSCAL does not.
EVIDENCE_COLLECTOR_OSCAL_NS = (
    "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/ns/oscal"
)


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


def _control_to_oscal(control: ControlDefinition, token: str) -> dict[str, Any]:
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
        "id": token,
        "uuid": _control_uuid(control.control_id),
        "class": _criticality_to_class(control.criticality),
        "title": control.name,
        "props": properties,
        "parts": parts,
    }


def export_oscal_catalog(controls: Iterable[ControlDefinition]) -> dict[str, Any]:
    """Render the catalog as a single OSCAL Catalog JSON document."""
    controls_list = list(controls)
    tokens = _control_tokens(c.control_id for c in controls_list)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for control in controls_list:
        grouped.setdefault(_group_for_framework(control.framework), []).append(
            _control_to_oscal(control, tokens[control.control_id])
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
    last_modified = _oscal_datetime(datetime.now(tz=UTC))

    document: dict[str, Any] = {
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
    finalized: dict[str, Any] = _finalize(document)
    return finalized


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
# A complete SHA-256 hex digest; anything else is left out of rlink hashes.
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}")


def _oscal_datetime(value: datetime) -> str:
    """Format ``value`` in UTC, converting rather than relabelling.

    An aware value used to be formatted with a hard-coded ``+00:00`` whatever
    its offset, so 18:30 at +05:30 was published as 18:30 UTC. A naive value
    is read as UTC, the convention the rest of the collector uses.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime(_OSCAL_DATETIME)


def _is_ncname(value: str) -> bool:
    return (
        bool(value)
        and (value[0].isalpha() or value[0] == "_")
        and all(ch.isalnum() or ch in ".-_" for ch in value)
    )


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


class OscalControlTokenCollisionError(ValueError):
    """Two distinct control ids in one document map to the same OSCAL token."""


def control_token(control_id: str) -> str:
    """The NCName token OSCAL uses for ``control_id``, from that id alone.

    The id lower-cased with dots replaced by dashes, when that is a valid
    NCName: the rule every release has used, so the shipped catalogs keep
    their tokens (``SSDF-PS.3`` -> ``ssdf-ps-3``). Otherwise (``1``,
    ``ORG:BUILD``, ``custom control``) the invalid characters become dashes,
    ``control-`` is prepended when the result does not start with a letter or
    underscore, and the first 8 hex digits of the id's SHA-256 are appended.

    The token depends on nothing but the id, so an OSCAL profile that selects
    ``org-build`` keeps matching whatever else the catalog contains. Ids that
    differ only by case or by ``.`` versus ``-`` share a token; see
    :func:`_control_tokens`.
    """
    token = control_id.lower().replace(".", "-")
    if _is_ncname(token):
        return token
    cleaned = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in token)
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"control-{cleaned}"
    return f"{cleaned}-{_short_hash(control_id)}"


def _control_tokens(control_ids: Iterable[str]) -> dict[str, str]:
    """Map each control id in one document to its :func:`control_token`.

    OSCAL control ids must be unique within a document. Two distinct ids that
    share a token (``ORG.BUILD`` and ``ORG-BUILD``) fail the export instead of
    being renamed: an earlier release appended a hash to both, which changed
    the token of an id a profile already referenced as soon as the other was
    added to the catalog.
    """
    tokens: dict[str, str] = {}
    owners: dict[str, str] = {}
    for control_id in dict.fromkeys(control_ids):
        token = control_token(control_id)
        other = owners.setdefault(token, control_id)
        if other != control_id:
            raise OscalControlTokenCollisionError(
                f"Control ids {other!r} and {control_id!r} both map to the OSCAL "
                f"control id {token!r}; OSCAL control ids must be unique within a "
                "document. Rename one of them in the catalog."
            )
        tokens[control_id] = token
    return tokens


def _prop_value(value: object) -> str:
    """A prop value as OSCAL's StringDatatype allows: no edge or inner line breaks."""
    return " ".join(str(value).split())


def _finalize(node: Any) -> Any:
    """Make a document satisfy OSCAL's array and string rules, whatever the input.

    Every OSCAL JSON array has ``minItems: 1`` and every prop value is a
    StringDatatype (no leading or trailing whitespace, no line break). Values
    come from operator-supplied bundles and catalogs, so instead of guarding
    each call site this pass collapses whitespace in prop values and media
    types, drops props and media types that end up empty, and removes any key
    whose list is empty (``observations`` and ``findings`` for a bundle with no
    evaluations, ``risks``, ``props``, ``include-controls``).
    """
    if isinstance(node, list):
        return [_finalize(item) for item in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key == "props" and isinstance(value, list):
            value = [
                {**prop, "value": _prop_value(prop.get("value", ""))}
                for prop in value
                if isinstance(prop, dict) and _prop_value(prop.get("value", ""))
            ]
        elif key == "media-type" and isinstance(value, str):
            value = _prop_value(value)
            if not value:
                continue
        value = _finalize(value)
        if isinstance(value, list) and not value:
            continue
        out[key] = value
    return out


def _assessment_scope(bundle: EvidenceBundle) -> str:
    """The subject every per-release uuid is scoped to.

    OSCAL finding, observation and result uuids are globally unique and
    assigned per subject. Two applications cut on the same release id (a
    calendar tag such as ``2026.04.10`` is common across an org) are two
    subjects, so the application name, its repository and the release id all
    seed the uuid, and so does the environment: the same release assessed in
    staging and in production is two subjects. JSON keeps the parts
    unambiguous whatever they contain.
    """
    return json.dumps(
        [
            bundle.application.name,
            bundle.application.repository,
            bundle.application.environment,
            bundle.release.release_id,
            bundle.release.commit_sha,
        ],
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


def _assessment_plan_uuid(scope: str) -> str:
    """Stable UUIDv5 for the embedded assessment-plan document itself."""
    return _scoped_uuid("ap-document", scope)


def _ssp_placeholder_uuid(scope: str) -> str:
    """Stable UUIDv5 for the resource the embedded plan's ``import-ssp`` names."""
    return _scoped_uuid("ssp", scope)


def _result_uuid(scope: str) -> str:
    """Stable UUIDv5 for the single assessment result this AR carries."""
    return _scoped_uuid("result", scope)


def _ar_uuid(scope: str, commit_sha: str) -> str:
    """Stable UUIDv5 for the top-level assessment-results document."""
    return _scoped_uuid("ar", scope, commit_sha)


def _evaluation_to_observation(
    evaluation: ControlEvaluation,
    scope: str,
    collected_iso: str,
) -> dict[str, Any]:
    # Each evidence ref links to a back-matter resource in this document. The
    # refs used to be hashed into `subjects[].subject-uuid` values that matched
    # nothing, so the evidence behind a finding could not be recovered.
    observation: dict[str, Any] = {
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
    }
    # OSCAL requires relevant-evidence to be non-empty when present, and a
    # control with no evidence at all (the usual not_ready case) has none.
    if evaluation.evidence_refs:
        observation["relevant-evidence"] = [
            {
                "href": f"#{_evidence_resource_uuid(scope, ref)}",
                "description": f"Evidence item {ref}",
            }
            for ref in evaluation.evidence_refs
        ]
    return observation


def _evaluation_to_finding(
    evaluation: ControlEvaluation,
    scope: str,
    tokens: dict[str, str],
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
            "target-id": tokens[evaluation.control_id],
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
        earliest = min(
            w.expires_at if w.expires_at.tzinfo else w.expires_at.replace(tzinfo=UTC)
            for w in waivers
        )
        risk["deadline"] = _oscal_datetime(earliest)
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
    collected_iso = _oscal_datetime(bundle.generated_at or datetime.now(tz=UTC))
    tokens = _control_tokens(ev.control_id for ev in bundle.control_evaluations)

    observations = [
        _evaluation_to_observation(ev, scope, collected_iso) for ev in bundle.control_evaluations
    ]
    findings = [_evaluation_to_finding(ev, scope, tokens) for ev in bundle.control_evaluations]
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
                    {"name": "environment", "value": bundle.application.environment},
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
                    "reviewed-controls": _reviewed_controls(
                        bundle, "Controls evaluated by this assessment", tokens
                    ),
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
            _assessment_plan_resource(bundle, scope, collected_iso),
            *_evidence_resources(bundle, scope),
        ]
    }
    finalized: dict[str, Any] = _finalize(document)
    return finalized


def _reviewed_controls(
    bundle: EvidenceBundle, description: str, tokens: dict[str, str]
) -> dict[str, Any]:
    return {
        "control-selections": [
            {
                "description": description,
                "include-controls": [
                    {"control-id": tokens[ev.control_id]} for ev in bundle.control_evaluations
                ],
            }
        ],
    }


def _catalog_props(bundle: EvidenceBundle) -> list[dict[str, str]]:
    if bundle.catalog is None:
        return []
    return [
        {"name": "catalog_origin", "value": bundle.catalog.origin},
        {"name": "catalog_name", "value": bundle.catalog.name},
        {"name": "catalog_sha256", "value": bundle.catalog.sha256},
    ]


def _assessment_plan(bundle: EvidenceBundle, scope: str, last_modified: str) -> dict[str, Any]:
    """A minimal OSCAL 1.1.2 assessment-plan generated from the same bundle.

    It carries the fields the AP model requires (uuid, metadata, import-ssp,
    reviewed-controls): the plan was to evaluate these controls against the
    catalog recorded in the bundle. The collector has no system security plan,
    so ``import-ssp`` resolves to a back-matter resource inside the plan that
    says so and names the application and repository assessed.
    """
    tokens = _control_tokens(ev.control_id for ev in bundle.control_evaluations)
    metadata: dict[str, Any] = {
        "title": (
            f"Assessment Plan · {bundle.application.name} · release {bundle.release.release_id}"
        ),
        "last-modified": last_modified,
        "version": __version__,
        "oscal-version": "1.1.2",
    }
    metadata["props"] = [
        {"name": "environment", "value": bundle.application.environment},
        *_catalog_props(bundle),
    ]
    no_ssp = (
        "No OSCAL system security plan is published. The system assessed is "
        f"{bundle.application.name} ({bundle.application.repository})."
    )
    return {
        "assessment-plan": {
            "uuid": _assessment_plan_uuid(scope),
            "metadata": metadata,
            "import-ssp": {"href": f"#{_ssp_placeholder_uuid(scope)}"},
            "reviewed-controls": _reviewed_controls(
                bundle, "Controls the release is evaluated against", tokens
            ),
            "back-matter": {
                "resources": [
                    {
                        "uuid": _ssp_placeholder_uuid(scope),
                        "title": "System under assessment",
                        "description": no_ssp,
                        # A resource needs an rlink or base64; the statement is
                        # the content, since there is no SSP to link to.
                        "base64": _base64_payload("no-ssp.txt", "text/plain", no_ssp),
                    }
                ]
            },
        }
    }


def _assessment_plan_resource(
    bundle: EvidenceBundle, scope: str, last_modified: str
) -> dict[str, Any]:
    """The back-matter resource ``import-ap`` resolves to.

    OSCAL requires ``import-ap``, and the collector publishes no separate plan
    file, so the plan is generated from the bundle and embedded here as base64.
    It first pointed at a fragment the document never defined, then at a
    resource holding only a title and a description, which resolved but was
    not an assessment plan.
    """
    plan = json.dumps(
        _finalize(_assessment_plan(bundle, scope, last_modified)),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    resource: dict[str, Any] = {
        "uuid": _assessment_plan_resource_uuid(scope),
        "title": "Assessment plan",
        "description": (
            "OSCAL assessment-plan generated from the evidence bundle: the controls "
            "evaluated and the catalog they were evaluated against."
        ),
        "base64": _base64_payload("assessment-plan.json", "application/oscal+json", plan),
    }
    props = _catalog_props(bundle)
    if props:
        resource["props"] = props
    return resource


def _base64_payload(filename: str, media_type: str, text: str) -> dict[str, str]:
    return {
        "filename": filename,
        "media-type": media_type,
        "value": base64.b64encode(text.encode("utf-8")).decode("ascii"),
    }


# Valid absolute URIs that a tool rendering the rlink href would execute or
# load inline; such a locator is embedded as the record instead of linked.
_UNLINKABLE_SCHEMES = frozenset({"javascript", "vbscript", "data"})


def _absolute_artifact_href(raw: RawEvidenceRef) -> str | None:
    r"""A link to where the artifact is, when that location is absolute.

    A relative ``artifact_path`` is relative to the collection root, but OSCAL
    resolves a relative rlink against the AR document itself, so linking it
    would point somewhere else. Only an RFC 3986 absolute URI (checked by
    ``is_absolute_uri``), or an absolute Windows or POSIX path (as a ``file:``
    URI), is linked; anything else is embedded as the record. A drive-relative Windows
    path such as ``C:reports\\scan.json`` has a drive but no root: it is not
    absolute, and ``as_uri()`` raises on it.
    """
    if (
        raw.artifact_uri
        and is_absolute_uri(raw.artifact_uri)
        and raw.artifact_uri.split(":", 1)[0].lower() not in _UNLINKABLE_SCHEMES
    ):
        return raw.artifact_uri
    path = raw.artifact_path
    if not path:
        return None
    windows = PureWindowsPath(path)
    if windows.drive and windows.is_absolute():
        return windows.as_uri()
    if path.startswith("/"):
        return PurePosixPath(path).as_uri()
    return None


def _ncname_filename(evidence_id: str) -> str:
    """A base64 ``filename`` that is a valid NCName whatever the evidence id."""
    return "evidence-" + re.sub(r"[^A-Za-z0-9._-]", "_", evidence_id) + ".json"


def _evidence_content(item: NormalizedEvidence | None, evidence_id: str) -> dict[str, Any]:
    """The rlink or base64 an OSCAL 1.1.2 back-matter resource must carry.

    A link to the artifact when its location is absolute; otherwise the
    normalized evidence record itself, so the resource still holds what the
    finding relied on, with a relative path recorded as a prop.
    """
    raw = item.raw if item is not None else None
    href = _absolute_artifact_href(raw) if raw is not None else None
    if raw is not None and href is not None:
        rlink: dict[str, Any] = {"href": href}
        if raw.content_type:
            rlink["media-type"] = raw.content_type
        digest = (raw.integrity_hash or "").removeprefix("sha256:")
        if (
            raw.integrity_hash
            and raw.integrity_hash.startswith("sha256:")
            and _SHA256.fullmatch(digest)
        ):
            rlink["hashes"] = [{"algorithm": "SHA-256", "value": digest}]
        return {"rlinks": [rlink]}
    record = (
        item.model_dump_json()
        if item is not None
        else json.dumps({"evidence_id": evidence_id, "present_in_bundle": False})
    )
    content: dict[str, Any] = {
        "base64": _base64_payload(_ncname_filename(evidence_id), "application/json", record)
    }
    location = (raw.artifact_path or raw.artifact_uri) if raw is not None else None
    if location:
        content["props"] = [
            {"name": "artifact-path", "ns": EVIDENCE_COLLECTOR_OSCAL_NS, "value": location}
        ]
    return content


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
        content = _evidence_content(item, evidence_id)
        resources.append(
            {
                "uuid": _evidence_resource_uuid(scope, evidence_id),
                "title": evidence_id,
                "description": description,
                "props": props + content.pop("props", []),
                **content,
            }
        )
    return resources
