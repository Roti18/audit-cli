"""Functional test driver.

Generate dan jalankan test case otomatis berdasarkan Registry:
  TC-F01  Endpoint Discovery – registry tidak kosong, tiap route punya method/path.
  TC-F02  Validasi Skema GET – GET dengan parameter dummy, cek status & JSON schema.
  TC-F03  Validasi Autentikasi – endpoint auth_required tanpa header, harapkan 401/403.
  TC-F04  Validasi Tipe Data – POST/PUT dengan tipe salah, harapkan 4xx.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jsonschema as jsc

from audit.schemas import (
    FunctionalResult,
    FunctionalTestCase,
    Param,
    ParamLocation,
    Registry,
    Route,
    save_json,
)

REQUEST_TIMEOUT = 10.0
MAX_REQUESTS = 200  # batas total request agar tidak spam target


# ---------------------------------------------------------------------------
# Dummy value generators
# ---------------------------------------------------------------------------

def _dummy_value(param_type: str) -> Any:
    """Return a valid dummy value for a given OpenAPI type string."""
    t = param_type.lower()
    if t in ("integer", "int", "int32", "int64", "number"):
        return 1
    if t == "boolean":
        return True
    if t == "array":
        return []
    return "test"


def _wrong_type_value(param_type: str) -> Any:
    """Return a deliberately wrong-typed value for a parameter."""
    t = param_type.lower()
    if t in ("integer", "int", "int32", "int64", "number"):
        return "not_a_number"
    if t == "boolean":
        return "not_a_bool"
    return 12345  # string field gets a number


def _build_url(target_url: str, route: Route, params: list[Param] | None = None) -> str:
    """Build full URL with path parameters filled in."""
    path = route.path
    for p in (params or route.params):
        if p.location == ParamLocation.path:
            path = path.replace(f"{{{p.name}}}", str(_dummy_value(p.type)))
    return target_url.rstrip("/") + path


def _build_query(route: Route) -> dict[str, Any]:
    """Extract query parameters with dummy values."""
    return {
        p.name: _dummy_value(p.type)
        for p in route.params
        if p.location == ParamLocation.query
    }


def _build_body_valid(route: Route) -> dict[str, Any] | None:
    """Build a valid-ish request body from the schema."""
    schema = route.request_body_schema
    if not schema:
        return None
    body: dict[str, Any] = {}
    props = schema.get("properties", {})
    for name, prop in props.items():
        body[name] = _dummy_value(prop.get("type", "string"))
    return body if body else {"data": "test"}


def _build_body_wrong_types(route: Route) -> dict[str, Any] | None:
    """Build a request body with intentionally wrong types."""
    schema = route.request_body_schema
    if not schema:
        return None
    body: dict[str, Any] = {}
    props = schema.get("properties", {})
    for name, prop in props.items():
        body[name] = _wrong_type_value(prop.get("type", "string"))
    return body if body else {"data": 99999}


# ---------------------------------------------------------------------------
# Test-case runners
# ---------------------------------------------------------------------------

def _tc_f01_discovery(registry: Registry) -> list[FunctionalTestCase]:
    """TC-F01: Registry not empty, each route has method & path."""
    cases: list[FunctionalTestCase] = []
    if len(registry.routes) == 0:
        cases.append(FunctionalTestCase(
            id="TC-F01-00", route="*", method="*",
            passed=False, expected="routes > 0",
            detail="Registry kosong",
        ))
        return cases

    for i, r in enumerate(registry.routes):
        ok = bool(r.method and r.path)
        cases.append(FunctionalTestCase(
            id=f"TC-F01-{i+1:02d}",
            route=r.path, method=r.method,
            passed=ok,
            expected="method & path not empty",
            detail="" if ok else f"method={r.method!r}, path={r.path!r}",
        ))
    return cases


def _tc_f02_schema_get(
    registry: Registry, client: httpx.Client, counter: list[int],
) -> list[FunctionalTestCase]:
    """TC-F02: GET endpoints – status code matches contract, body validates."""
    cases: list[FunctionalTestCase] = []
    get_routes = [r for r in registry.routes if r.method == "GET"]
    for i, route in enumerate(get_routes):
        if counter[0] >= MAX_REQUESTS:
            break
        url = _build_url(registry.target_url, route)
        query = _build_query(route)
        try:
            resp = client.get(url, params=query, timeout=REQUEST_TIMEOUT)
            counter[0] += 1
        except httpx.RequestError as exc:
            cases.append(FunctionalTestCase(
                id=f"TC-F02-{i+1:02d}", route=route.path, method="GET",
                passed=False, expected="2xx", detail=f"Request error: {exc}",
            ))
            continue

        # Check if any expected status code matches
        expected_statuses = [int(s) for s in route.response_schemas.keys() if s.isdigit()]
        if not expected_statuses:
            expected_statuses = [200]

        status_ok = resp.status_code in expected_statuses

        # JSON schema validation (best-effort)
        schema_ok = True
        schema_detail = ""
        resp_schema = route.response_schemas.get(str(resp.status_code))
        if resp_schema and resp.headers.get("content-type", "").startswith("application/json"):
            try:
                body = resp.json()
                jsc.validate(body, resp_schema)
            except jsc.ValidationError as ve:
                schema_ok = False
                schema_detail = f" | schema mismatch: {ve.message[:120]}"
            except Exception:
                pass  # non-JSON or parse error – skip validation

        passed = status_ok and schema_ok
        cases.append(FunctionalTestCase(
            id=f"TC-F02-{i+1:02d}", route=route.path, method="GET",
            passed=passed,
            expected=f"status in {expected_statuses}",
            actual_status=resp.status_code,
            detail=f"status={'OK' if status_ok else 'MISMATCH'}{schema_detail}",
        ))
    return cases


def _tc_f03_auth(
    registry: Registry, client: httpx.Client, counter: list[int],
) -> list[FunctionalTestCase]:
    """TC-F03: Auth-required endpoints called without auth -> 401/403."""
    cases: list[FunctionalTestCase] = []
    auth_routes = [r for r in registry.routes if r.auth_required]
    for i, route in enumerate(auth_routes):
        if counter[0] >= MAX_REQUESTS:
            break
        url = _build_url(registry.target_url, route)
        try:
            if route.method in ("POST", "PUT", "PATCH"):
                body = _build_body_valid(route) or {}
                resp = client.request(route.method, url, json=body, timeout=REQUEST_TIMEOUT)
            else:
                query = _build_query(route)
                resp = client.request(route.method, url, params=query, timeout=REQUEST_TIMEOUT)
            counter[0] += 1
        except httpx.RequestError as exc:
            cases.append(FunctionalTestCase(
                id=f"TC-F03-{i+1:02d}", route=route.path, method=route.method,
                passed=False, expected="401 or 403",
                detail=f"Request error: {exc}",
            ))
            continue

        passed = resp.status_code in (401, 403)
        cases.append(FunctionalTestCase(
            id=f"TC-F03-{i+1:02d}", route=route.path, method=route.method,
            passed=passed,
            expected="401 or 403",
            actual_status=resp.status_code,
            detail="" if passed else f"got {resp.status_code} instead of 401/403",
        ))
    return cases


def _tc_f04_type_validation(
    registry: Registry, client: httpx.Client, counter: list[int],
) -> list[FunctionalTestCase]:
    """TC-F04: POST/PUT with wrong types -> expect 4xx."""
    cases: list[FunctionalTestCase] = []
    write_routes = [r for r in registry.routes if r.method in ("POST", "PUT", "PATCH")
                    and r.request_body_schema]
    for i, route in enumerate(write_routes):
        if counter[0] >= MAX_REQUESTS:
            break
        url = _build_url(registry.target_url, route)
        body = _build_body_wrong_types(route)
        try:
            resp = client.request(route.method, url, json=body, timeout=REQUEST_TIMEOUT)
            counter[0] += 1
        except httpx.RequestError as exc:
            cases.append(FunctionalTestCase(
                id=f"TC-F04-{i+1:02d}", route=route.path, method=route.method,
                passed=False, expected="4xx",
                detail=f"Request error: {exc}",
            ))
            continue

        passed = 400 <= resp.status_code < 500
        cases.append(FunctionalTestCase(
            id=f"TC-F04-{i+1:02d}", route=route.path, method=route.method,
            passed=passed,
            expected="4xx (400-499)",
            actual_status=resp.status_code,
            detail="" if passed else f"got {resp.status_code}",
        ))
    return cases


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_functional(
    registry: Registry,
    run_id: str = "default",
    out_dir: str | None = None,
    client: httpx.Client | None = None,
) -> FunctionalResult:
    """Execute all functional test cases against the target.

    Args:
        registry: Parsed API registry.
        run_id: Identifier for this audit run.
        out_dir: Directory for output file. Defaults to results/<run_id>.
        client: Optional httpx.Client (useful for testing with mock transport).

    Returns:
        FunctionalResult with per-test-case details.
    """
    from pathlib import Path

    own_client = client is None
    if own_client:
        # Create client WITHOUT auth header to test unauthenticated behavior
        client = httpx.Client(follow_redirects=True)

    counter = [0]  # mutable counter for request limiting

    t0 = time.perf_counter()
    all_cases: list[FunctionalTestCase] = []

    # TC-F01
    all_cases.extend(_tc_f01_discovery(registry))

    # TC-F02 – F04 (network tests)
    try:
        all_cases.extend(_tc_f02_schema_get(registry, client, counter))
        all_cases.extend(_tc_f03_auth(registry, client, counter))
        all_cases.extend(_tc_f04_type_validation(registry, client, counter))
    except Exception as exc:
        all_cases.append(FunctionalTestCase(
            id="TC-ERR", route="*", method="*",
            passed=False, expected="no crash",
            detail=f"Driver error: {exc}",
        ))
    finally:
        if own_client:
            client.close()

    elapsed = time.perf_counter() - t0

    total = len(all_cases)
    passed = sum(1 for c in all_cases if c.passed)

    result = FunctionalResult(
        run_id=run_id,
        test_cases=all_cases,
        total=total,
        passed=passed,
        failed=total - passed,
        pass_rate=round(passed / total, 4) if total else 0.0,
    )

    # Save output
    if out_dir is None:
        out_dir = str(Path("results") / run_id)
    out_path = Path(out_dir) / "functional.json"
    save_json(result, out_path)
    print(f"[functional] {passed}/{total} passed ({result.pass_rate*100:.1f}%) in {elapsed:.2f}s")
    print(f"[functional] Output: {out_path}")

    return result
