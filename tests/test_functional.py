"""Tests for drivers/functional.py – tanpa jaringan, pakai mock httpx transport."""

from __future__ import annotations

import json
import pytest

import httpx

from audit.schemas import (
    FunctionalResult,
    Param,
    ParamLocation,
    Registry,
    Route,
)
from audit.drivers.functional import run_functional


# ---------------------------------------------------------------------------
# Mock transport
# ---------------------------------------------------------------------------

class MockTransport(httpx.BaseTransport):
    """Transport mock yang mengembalikan response berdasarkan path."""

    def __init__(self, routes_behavior: dict | None = None):
        # routes_behavior: {(method, path): (status, body_dict)}
        self._routes = routes_behavior or {}
        self._default_body = {"status": "ok"}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method.upper()

        # Match exact path first, then with path params
        key = (method, path)
        if key in self._routes:
            status, body = self._routes[key]
        else:
            # Fallback: 200 for GET, 201 for POST, 401 for auth-required patterns
            if "/unauthorized" in path:
                status, body = 401, {"error": "Unauthorized"}
            elif method == "POST":
                status, body = 201, {"id": 1}
            elif method == "GET":
                status, body = 200, self._default_body
            else:
                status, body = 200, self._default_body

        return httpx.Response(
            status_code=status,
            json=body,
            headers={"content-type": "application/json"},
        )


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_registry(routes: list[Route], target: str = "http://localhost:9999") -> Registry:
    return Registry(target_url=target, source="openapi", routes=routes)


def _make_route(
    method: str = "GET",
    path: str = "/test",
    params: list[Param] | None = None,
    request_body_schema: dict | None = None,
    response_schemas: dict | None = None,
    auth_required: bool = False,
) -> Route:
    return Route(
        method=method,
        path=path,
        params=params or [],
        request_body_schema=request_body_schema,
        response_schemas=response_schemas or {},
        auth_required=auth_required,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTCF01Discovery:
    def test_non_empty_registry(self, tmp_path):
        reg = _make_registry([_make_route()])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f01 = [tc for tc in result.test_cases if tc.id.startswith("TC-F01")]
        assert len(f01) > 0
        assert all(tc.passed for tc in f01)

    def test_empty_registry(self, tmp_path):
        reg = _make_registry([])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f01 = [tc for tc in result.test_cases if tc.id.startswith("TC-F01")]
        assert len(f01) == 1
        assert not f01[0].passed


class TestTCF02SchemaGET:
    def test_valid_get_response(self, tmp_path):
        route = _make_route(
            method="GET", path="/items",
            response_schemas={"200": {"type": "object"}},
        )
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f02 = [tc for tc in result.test_cases if tc.id.startswith("TC-F02")]
        assert len(f02) == 1
        assert f02[0].passed

    def test_wrong_status_code(self, tmp_path):
        route = _make_route(
            method="GET", path="/notfound",
            response_schemas={"200": {"type": "object"}},
        )
        behavior = {("GET", "/notfound"): (404, {"error": "not found"})}
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport(behavior))
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f02 = [tc for tc in result.test_cases if tc.id.startswith("TC-F02")]
        assert len(f02) == 1
        assert not f02[0].passed

    def test_schema_mismatch(self, tmp_path):
        route = _make_route(
            method="GET", path="/items",
            response_schemas={
                "200": {
                    "type": "object",
                    "required": ["data"],
                    "properties": {"data": {"type": "array"}},
                },
            },
        )
        # Mock returns {"status": "ok"} which doesn't have "data"
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f02 = [tc for tc in result.test_cases if tc.id.startswith("TC-F02")]
        assert len(f02) == 1
        assert not f02[0].passed


class TestTCF03Auth:
    def test_auth_endpoint_returns_401(self, tmp_path):
        route = _make_route(
            method="GET", path="/unauthorized/resource",
            auth_required=True,
        )
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f03 = [tc for tc in result.test_cases if tc.id.startswith("TC-F03")]
        assert len(f03) == 1
        assert f03[0].passed

    def test_auth_endpoint_does_not_return_401(self, tmp_path):
        route = _make_route(
            method="GET", path="/open/resource",
            auth_required=True,
        )
        # MockTransport returns 200 for /open/resource
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f03 = [tc for tc in result.test_cases if tc.id.startswith("TC-F03")]
        assert len(f03) == 1
        assert not f03[0].passed


class TestTCF04TypeValidation:
    def test_wrong_type_returns_400(self, tmp_path):
        route = _make_route(
            method="POST", path="/create",
            request_body_schema={
                "type": "object",
                "properties": {
                    "count": {"type": "integer"},
                    "name": {"type": "string"},
                },
            },
        )
        behavior = {("POST", "/create"): (400, {"error": "bad request"})}
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport(behavior))
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f04 = [tc for tc in result.test_cases if tc.id.startswith("TC-F04")]
        assert len(f04) == 1
        assert f04[0].passed

    def test_wrong_type_returns_200_fails(self, tmp_path):
        route = _make_route(
            method="POST", path="/create",
            request_body_schema={
                "type": "object",
                "properties": {"count": {"type": "integer"}},
            },
        )
        # Mock returns 201 (server didn't validate)
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        f04 = [tc for tc in result.test_cases if tc.id.startswith("TC-F04")]
        assert len(f04) == 1
        assert not f04[0].passed


class TestFunctionalOutputFile:
    def test_output_file_created(self, tmp_path):
        route = _make_route()
        reg = _make_registry([route])
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        out_file = tmp_path / "functional.json"
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["total"] == result.total
        assert data["passed"] == result.passed

    def test_pass_rate_calculation(self, tmp_path):
        routes = [
            _make_route(method="GET", path="/ok"),
            _make_route(method="GET", path="/also-ok"),
        ]
        reg = _make_registry(routes)
        client = httpx.Client(transport=MockTransport())
        result = run_functional(reg, run_id="test", out_dir=str(tmp_path), client=client)
        client.close()
        # F01 should pass for both routes, F02 should pass for both
        assert result.total > 0
        assert 0.0 <= result.pass_rate <= 1.0
