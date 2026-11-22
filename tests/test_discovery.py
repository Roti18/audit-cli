"""Tests for discovery/openapi.py – parser Swagger 2 & OpenAPI 3, $ref, spec kosong."""

from __future__ import annotations

import json
import pytest
import yaml

from audit.discovery.openapi import discover, _parse_spec, _resolve_ref, _deep_resolve


# ---------------------------------------------------------------------------
# Fixtures: synthetic specs
# ---------------------------------------------------------------------------

def _make_openapi3_spec(n_endpoints: int = 50) -> dict:
    """Generate a synthetic OpenAPI 3.0 spec with *n_endpoints* GET endpoints."""
    paths = {}
    for i in range(n_endpoints):
        paths[f"/items/{i}"] = {
            "get": {
                "summary": f"Get item {i}",
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "integer"}},
                    {"name": "q", "in": "query", "required": False,
                     "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "integer"},
                                        "name": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
        }
    return {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic", "version": "1.0"},
        "paths": paths,
    }


def _make_swagger2_spec() -> dict:
    """Generate a simple Swagger 2.0 spec with $ref."""
    return {
        "swagger": "2.0",
        "info": {"title": "Swagger2 Test", "version": "1.0"},
        "basePath": "/",
        "paths": {
            "/pets": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "type": "integer", "required": False},
                    ],
                    "responses": {
                        "200": {
                            "description": "OK",
                            "schema": {"$ref": "#/definitions/PetList"},
                        },
                    },
                },
                "post": {
                    "parameters": [
                        {
                            "name": "body",
                            "in": "body",
                            "schema": {"$ref": "#/definitions/Pet"},
                        },
                    ],
                    "responses": {
                        "201": {"description": "Created"},
                    },
                    "security": [{"api_key": []}],
                },
            },
        },
        "definitions": {
            "Pet": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                },
            },
            "PetList": {
                "type": "array",
                "items": {"$ref": "#/definitions/Pet"},
            },
        },
        "securityDefinitions": {
            "api_key": {"type": "apiKey", "name": "X-API-Key", "in": "header"},
        },
    }


def _make_spec_with_circular_ref() -> dict:
    """Spec with circular $ref to test cycle guard."""
    return {
        "openapi": "3.0.3",
        "info": {"title": "Circular", "version": "1.0"},
        "paths": {
            "/nodes": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Node"},
                                },
                            },
                        },
                    },
                },
            },
        },
        "components": {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "children": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/Node"},
                        },
                    },
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRefResolution:
    def test_simple_ref(self):
        root = {"definitions": {"Foo": {"type": "object", "properties": {"x": {"type": "integer"}}}}}
        result = _resolve_ref("#/definitions/Foo", root)
        assert result["type"] == "object"

    def test_nested_ref(self):
        root = {
            "definitions": {
                "A": {"$ref": "#/definitions/B"},
                "B": {"type": "string"},
            },
        }
        result = _resolve_ref("#/definitions/A", root)
        assert result["type"] == "string"

    def test_circular_ref_does_not_crash(self):
        root = {
            "definitions": {
                "A": {"$ref": "#/definitions/B"},
                "B": {"$ref": "#/definitions/A"},
            },
        }
        result = _resolve_ref("#/definitions/A", root)
        # Should return {} due to cycle guard, not raise
        assert isinstance(result, dict)

    def test_deep_resolve_with_ref(self):
        root = {
            "components": {
                "schemas": {
                    "Item": {"type": "object", "properties": {"name": {"type": "string"}}},
                },
            },
        }
        schema = {"$ref": "#/components/schemas/Item"}
        resolved = _deep_resolve(schema, root)
        assert resolved.get("type") == "object"


class TestParseOpenAPI3:
    def test_parse_50_endpoints(self):
        spec = _make_openapi3_spec(50)
        registry = _parse_spec(spec, "http://localhost:8000", None)
        assert len(registry.routes) == 50
        for r in registry.routes:
            assert r.method == "GET"
            assert r.path.startswith("/items/")
            assert len(r.params) == 2

    def test_response_schema_resolved(self):
        spec = _make_openapi3_spec(1)
        registry = _parse_spec(spec, "http://localhost:8000", None)
        route = registry.routes[0]
        assert "200" in route.response_schemas
        schema = route.response_schemas["200"]
        assert schema["type"] == "object"

    def test_circular_ref_spec(self):
        spec = _make_spec_with_circular_ref()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        assert len(registry.routes) == 1


class TestParseSwagger2:
    def test_basic_swagger2(self):
        spec = _make_swagger2_spec()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        assert len(registry.routes) == 2  # GET + POST

        get_route = [r for r in registry.routes if r.method == "GET"][0]
        assert get_route.path == "/pets"
        assert len(get_route.params) == 1
        assert get_route.params[0].name == "limit"

    def test_swagger2_body_param(self):
        spec = _make_swagger2_spec()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        post_route = [r for r in registry.routes if r.method == "POST"][0]
        assert post_route.request_body_schema is not None
        assert post_route.request_body_schema.get("type") == "object"

    def test_swagger2_security(self):
        spec = _make_swagger2_spec()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        post_route = [r for r in registry.routes if r.method == "POST"][0]
        assert post_route.auth_required is True
        get_route = [r for r in registry.routes if r.method == "GET"][0]
        assert get_route.auth_required is False

    def test_ref_in_response(self):
        spec = _make_swagger2_spec()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        get_route = [r for r in registry.routes if r.method == "GET"][0]
        resp_schema = get_route.response_schemas.get("200", {})
        assert resp_schema.get("type") == "array"


class TestEmptySpec:
    def test_empty_paths(self):
        spec = {"openapi": "3.0.3", "info": {"title": "E", "version": "1"}, "paths": {}}
        registry = _parse_spec(spec, "http://localhost:8000", None)
        assert len(registry.routes) == 0

    def test_no_paths_key(self):
        spec = {"openapi": "3.0.3", "info": {"title": "E", "version": "1"}}
        registry = _parse_spec(spec, "http://localhost:8000", None)
        assert len(registry.routes) == 0


class TestDiscoverFromFile:
    def test_discover_local_yaml(self, tmp_path):
        """discover() with a local YAML spec file."""
        spec = _make_openapi3_spec(5)
        spec_file = tmp_path / "spec.yaml"
        spec_file.write_text(yaml.dump(spec), encoding="utf-8")

        registry = discover("http://localhost:8000", spec_path=str(spec_file))
        assert len(registry.routes) == 5

    def test_discover_local_json(self, tmp_path):
        """discover() with a local JSON spec file."""
        spec = _make_swagger2_spec()
        spec_file = tmp_path / "spec.json"
        spec_file.write_text(json.dumps(spec), encoding="utf-8")

        registry = discover("http://localhost:8000", spec_path=str(spec_file))
        assert len(registry.routes) == 2


class TestPerformance:
    def test_parse_50_endpoints_under_5_seconds(self):
        """Parsing 50 endpoints should take < 5 seconds."""
        import time
        spec = _make_openapi3_spec(50)
        t0 = time.perf_counter()
        registry = _parse_spec(spec, "http://localhost:8000", None)
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"Parsing took {elapsed:.2f}s (> 5s)"
        assert len(registry.routes) == 50
