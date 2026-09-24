"""Tests for the optional FastAPI surface (`[api]` extra).

These tests skip cleanly when fastapi is not installed, so the unit
suite still works on a minimal install.
"""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from evidence_collector import __version__  # noqa: E402
from evidence_collector.api.app import build_app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(build_app())


def test_healthz_returns_ok(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_version_matches_package(client: TestClient) -> None:
    response = client.get("/version")
    assert response.status_code == 200
    assert response.json() == {"version": __version__}


def test_schema_returns_json_schema(client: TestClient) -> None:
    response = client.get("/schema")
    assert response.status_code == 200
    payload = response.json()
    # Pydantic's model_json_schema produces a Draft 2020-12 document
    # with `properties` and `required` at the top level.
    assert "properties" in payload
    assert "required" in payload


def test_catalog_returns_thirteen_controls(client: TestClient) -> None:
    response = client.get("/catalog")
    assert response.status_code == 200
    payload = response.json()
    assert isinstance(payload, list)
    # Default catalog has 13 controls per CHANGELOG 1.0.0; this test
    # also locks the count so accidental additions are visible.
    assert len(payload) == 13
    assert all("control_id" in c for c in payload)


def test_plugins_lists_builtin_groups(client: TestClient) -> None:
    response = client.get("/plugins")
    assert response.status_code == 200
    payload = response.json()
    assert "parsers" in payload
    assert "collectors" in payload
    assert "sarif" in payload["parsers"]
    assert "local" in payload["collectors"]


def test_interactive_docs_are_off_unless_asked_for() -> None:
    """The code said `/docs` was off by default and then served it.

    `docs_url="/docs"` sat directly under a comment reading "No /docs in
    production by default", while `redoc_url=None` beside it was correct — one
    of the two was disabled and the other was not. Nothing sensitive is exposed
    either way (every endpoint is read-only and returns the published schema,
    the control catalog or plugin names); the defect is the expectation it set,
    since an operator reading that comment would expose the port believing the
    interactive surface was closed.
    """
    closed = TestClient(build_app())

    assert closed.get("/docs").status_code == 404
    # The spec follows the UI: serving it while claiming the UI is off would be
    # the same half-measure.
    assert closed.get("/openapi.json").status_code == 404
    # The actual API is unaffected.
    assert closed.get("/healthz").status_code == 200
    assert closed.get("/schema").status_code == 200


def test_docs_can_be_opted_into_explicitly() -> None:
    opted_in = TestClient(build_app(expose_docs=True))

    assert opted_in.get("/docs").status_code == 200
    assert opted_in.get("/openapi.json").status_code == 200


def test_docs_can_be_opted_into_by_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deploy-time opt-in without a code change."""
    monkeypatch.setenv("SDLC_EVIDENCE_API_DOCS", "1")

    assert TestClient(build_app()).get("/docs").status_code == 200

    monkeypatch.setenv("SDLC_EVIDENCE_API_DOCS", "0")

    assert TestClient(build_app()).get("/docs").status_code == 404
