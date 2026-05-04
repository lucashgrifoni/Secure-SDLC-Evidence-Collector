"""Optional FastAPI surface.

The collector is CLI-first; this module exists so platform teams that
need a network-callable surface can ``pip install secure-sdlc-evidence-collector[api]``
and get a small REST API without committing to a new deployment shape.

The API mirrors the CLI surface, not the underlying Python API:

- ``GET  /healthz``           — liveness probe
- ``GET  /version``           — package version
- ``GET  /schema``            — JSON Schema for the bundle
- ``GET  /catalog``           — control catalog as JSON
- ``GET  /plugins``           — registered parser/collector plugins

The pipeline-driving endpoint (``POST /run``) is deliberately omitted
from the 1.x surface: running a pipeline requires filesystem access and
is best done from a CI runner, not a long-lived HTTP service. If you
need to drive runs over HTTP, build it on top of ``run_pipeline()``
yourself — that is a deliberate Tier 4 decision and is documented.

Importing this module requires the ``api`` extra:

    pip install "secure-sdlc-evidence-collector[api]"
"""

from __future__ import annotations

# `app` is exposed lazily so importing the package without the [api]
# extra does not crash. The lazy attribute resolves on first access.

_app = None


def get_app() -> object:
    """Return (and lazily build) the FastAPI app."""
    global _app
    if _app is None:
        from evidence_collector.api.app import build_app

        _app = build_app()
    return _app


__all__ = ["get_app"]
