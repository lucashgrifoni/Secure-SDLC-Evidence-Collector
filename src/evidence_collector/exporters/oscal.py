"""OSCAL Catalog exporter.

Auditors and government compliance frameworks (FedRAMP, HITRUST,
StateRAMP, OSCAL-aware GRC tools) speak NIST OSCAL natively. This
exporter renders the project's control catalog as an OSCAL Catalog
Model JSON document conformant with the OSCAL 1.1.x schema.

We do **not** yet emit the OSCAL Assessment Plan / Assessment Results
models — those would require mapping the bundle's evaluations into
OSCAL-specific shapes (subjects, observations, findings) that are
worth their own ADR. The Catalog is the highest-leverage starting
point because it is what auditor tooling wants for on-boarding.

Reference: https://pages.nist.gov/OSCAL/concepts/layer/control/catalog/
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from evidence_collector import __version__
from evidence_collector.domain.enums import ControlCriticality, ControlFramework
from evidence_collector.domain.models import ControlDefinition

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
