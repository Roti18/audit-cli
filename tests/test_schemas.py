"""Tests for schemas.py – serialization / deserialization round-trip."""

from __future__ import annotations

import json
import pytest

from audit.schemas import (
    Finding,
    FunctionalResult,
    FunctionalTestCase,
    Param,
    ParamLocation,
    Registry,
    Route,
    Severity,
    load_json,
    save_json,
)


class TestParamAlias:
    def test_param_in_alias(self):
        """Param field 'location' should serialize as 'in'."""
        p = Param(name="id", **{"in": "path"}, type="integer", required=True)
        assert p.location == ParamLocation.path
        d = p.model_dump(by_alias=True)
        assert "in" in d
        assert d["in"] == "path"

    def test_param_from_dict_with_in(self):
        p = Param.model_validate({"name": "q", "in": "query", "type": "string"})
        assert p.location == ParamLocation.query


class TestRegistryRoundTrip:
    def test_save_load(self, tmp_path):
        route = Route(
            method="GET",
            path="/test/{id}",
            params=[Param(name="id", **{"in": "path"}, type="integer", required=True)],
            response_schemas={"200": {"type": "object"}},
            auth_required=True,
        )
        reg = Registry(target_url="http://localhost:3000", routes=[route], auth_header="Bearer x")
        path = tmp_path / "registry.json"
        save_json(reg, path)
        loaded = load_json(Registry, path)
        assert loaded.target_url == reg.target_url
        assert len(loaded.routes) == 1
        assert loaded.routes[0].method == "GET"
        assert loaded.routes[0].auth_required is True
        assert loaded.routes[0].params[0].name == "id"


class TestFinding:
    def test_severity_enum(self):
        f = Finding(
            tool="zap", name="SQL Injection", cwe="CWE-89",
            route="/test", method="GET", severity="High", cvss=7.5,
        )
        assert f.severity == Severity.high

    def test_serialize(self, tmp_path):
        f = Finding(
            tool="nuclei", name="XSS", route="/search", method="GET",
            severity="Medium",
        )
        path = tmp_path / "finding.json"
        save_json(f, path)
        data = json.loads(path.read_text())
        assert data["severity"] == "Medium"


class TestFunctionalResult:
    def test_round_trip(self, tmp_path):
        tc = FunctionalTestCase(
            id="TC-F01-01", route="/test", method="GET",
            passed=True, expected="200", actual_status=200,
        )
        result = FunctionalResult(
            run_id="test-run",
            test_cases=[tc],
            total=1, passed=1, failed=0, pass_rate=1.0,
        )
        path = tmp_path / "functional.json"
        save_json(result, path)
        loaded = load_json(FunctionalResult, path)
        assert loaded.total == 1
        assert loaded.test_cases[0].passed is True
