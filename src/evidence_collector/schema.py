"""Canonical, self-describing JSON Schema for the ``EvidenceBundle`` contract.

Pydantic emits a Draft 2020-12 document for ``EvidenceBundle`` but omits the
dialect (``$schema``) and identity (``$id``) keywords. We prepend both so the
emitted contract validates in editors out of the box and is ready for public
registries (e.g. SchemaStore). This is the single source of truth shared by the
``sdlc-evidence schema`` CLI command, the optional HTTP ``/schema`` endpoint,
the committed ``docs/evidence-bundle.schema.json`` artifact, and its freshness
test — so the four can never drift.
"""

from __future__ import annotations

import json
from typing import Any

from evidence_collector.domain.models import EvidenceBundle

#: JSON Schema dialect Pydantic v2 targets.
BUNDLE_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"

#: Stable canonical identity. Served from the project's GitHub Pages docs site;
#: editors and registries resolve the contract here.
BUNDLE_SCHEMA_ID = (
    "https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector"
    "/docs/evidence-bundle.schema.json"
)


def bundle_json_schema() -> dict[str, Any]:
    """Return the ``EvidenceBundle`` JSON Schema, made self-describing.

    Prepends ``$schema`` and ``$id`` to Pydantic's generated document.
    """
    schema = EvidenceBundle.model_json_schema()
    return {"$schema": BUNDLE_SCHEMA_DIALECT, "$id": BUNDLE_SCHEMA_ID, **schema}


def bundle_json_schema_text() -> str:
    """Return the canonical serialization — the exact bytes of the artifact.

    Deterministic (``sort_keys``) with a trailing newline, so the committed
    ``docs/evidence-bundle.schema.json`` is byte-for-byte reproducible.
    """
    return json.dumps(bundle_json_schema(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
