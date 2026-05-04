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
