"""FastAPI app factory for the optional REST surface.

Kept intentionally small: read-only endpoints that mirror the CLI's
non-pipeline commands. Filesystem mutations live on the CLI side
exclusively.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from evidence_collector import __version__
from evidence_collector.controls import default_catalog
from evidence_collector.domain.models import EvidenceBundle
from evidence_collector.plugins import list_plugins


def build_app() -> FastAPI:
    api = FastAPI(
        title="Secure SDLC Evidence Collector",
        description=(
            "Optional REST surface for read-only operations. The pipeline "
            "remains CLI-first; this API exposes only the stateless "
            "endpoints (schema, catalog, plugins, version, health)."
        ),
        version=__version__,
        # No /docs in production by default — a downstream operator can
        # opt into Swagger by setting docs_url at deploy time.
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
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
        return EvidenceBundle.model_json_schema()

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
