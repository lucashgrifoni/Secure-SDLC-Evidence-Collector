"""FastAPI app factory for the optional REST surface.

Kept intentionally small: read-only endpoints that mirror the CLI's
non-pipeline commands. Filesystem mutations live on the CLI side
exclusively.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI

from evidence_collector import __version__
from evidence_collector.controls import default_catalog
from evidence_collector.plugins import list_plugins
from evidence_collector.schema import bundle_json_schema


def build_app(*, expose_docs: bool | None = None) -> FastAPI:
    """Build the read-only REST surface.

    `expose_docs` controls the interactive documentation. It defaults to off,
    and to what the surrounding comment always claimed: the previous code said
    "No /docs in production by default" and then passed `docs_url="/docs"`,
    which serves Swagger UI. `redoc_url=None` beside it was correct, so one of
    the two was disabled and the other was not.

    Nothing sensitive was exposed — every endpoint here is read-only and
    returns the published schema, the control catalog or plugin names. The
    defect is in the expectation it set: an operator who read that comment
    would believe the interactive surface was off and could expose the port on
    that basis. Default-closed with an explicit opt-in is what the comment
    described, so that is what it does now.

    Set `SDLC_EVIDENCE_API_DOCS=1` to opt in at deploy time without code
    changes, or pass `expose_docs=True` when embedding the app.
    """
    if expose_docs is None:
        expose_docs = os.environ.get("SDLC_EVIDENCE_API_DOCS", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    api = FastAPI(
        title="Secure SDLC Evidence Collector",
        description=(
            "Optional REST surface for read-only operations. The pipeline "
            "remains CLI-first; this API exposes only the stateless "
            "endpoints (schema, catalog, plugins, version, health)."
        ),
        version=__version__,
        docs_url="/docs" if expose_docs else None,
        redoc_url=None,
        # The OpenAPI document follows the docs UI: serving the spec while
        # claiming the UI is off would be the same half-measure again.
        openapi_url="/openapi.json" if expose_docs else None,
    )

    @api.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        """Liveness probe — never reaches the catalog or filesystem."""
        return {"status": "ok"}

    @api.get("/version", tags=["meta"])
    def version() -> dict[str, str]:
        return {"version": __version__}

    @api.get("/schema", tags=["meta"])
    def schema() -> dict[str, Any]:
        return bundle_json_schema()

    @api.get("/catalog", tags=["meta"])
    def catalog() -> list[dict[str, Any]]:
        # Return JSON-friendly representations (Pydantic dumps).
        return [c.model_dump() for c in default_catalog()]

    @api.get("/plugins", tags=["meta"])
    def plugins() -> dict[str, list[str]]:
        return list_plugins()

    return api


# Convenience target for `uvicorn evidence_collector.api.app:app`.
app = build_app()
