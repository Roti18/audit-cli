"""OpenAPI / Swagger spec discovery & parsing.

Mendukung OpenAPI 3.0.x (JSON/YAML) dan Swagger 2.0.
Melakukan $ref resolution (rekursif, tahan siklus).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx
import yaml

from audit.schemas import Param, ParamLocation, Registry, Route, save_json

# Paths yang umum di-probe jika user tidak memberikan spec
_COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
]

TIMEOUT = 3.0  # detik per probe


# ---------------------------------------------------------------------------
# $ref resolver (cycle-safe)
# ---------------------------------------------------------------------------

def _resolve_ref(ref: str, root: dict, _seen: set | None = None) -> dict:
    """Resolve a JSON $ref pointer against *root*, with cycle guard."""
    if _seen is None:
        _seen = set()
    if ref in _seen:
        return {}  # break cycle
    _seen.add(ref)

    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node: Any = root
    for p in parts:
        p = p.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            node = node.get(p, {})
        else:
            return {}
    if isinstance(node, dict) and "$ref" in node:
        return _resolve_ref(node["$ref"], root, _seen)
    return node if isinstance(node, dict) else {}


def _deep_resolve(schema: Any, root: dict, _seen: set | None = None) -> Any:
    """Recursively resolve all $ref inside a schema dict."""
    if _seen is None:
        _seen = set()
    if not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in _seen:
            return {}
        _seen.add(ref)
        resolved = _resolve_ref(ref, root, set())
        return _deep_resolve(resolved, root, _seen)
    return {k: _deep_resolve(v, root, _seen) for k, v in schema.items()}


# ---------------------------------------------------------------------------
# Spec loader
# ---------------------------------------------------------------------------

def _load_spec_from_path(spec_path: str) -> dict:
    """Load spec from local file or URL."""
    p = Path(spec_path)
    if p.exists():
        text = p.read_text(encoding="utf-8")
    elif spec_path.startswith(("http://", "https://")):
        resp = httpx.get(spec_path, timeout=TIMEOUT)
        resp.raise_for_status()
        text = resp.text
    else:
        raise FileNotFoundError(f"Spec not found: {spec_path}")
    # Try JSON first, fallback YAML
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


def _probe_spec(target_url: str, auth_header: str | None = None) -> dict | None:
    """Probe common spec paths on the target."""
    headers = {}
    if auth_header:
        k, _, v = auth_header.partition(":")
        headers[k.strip()] = v.strip()
    for path in _COMMON_SPEC_PATHS:
        url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            resp = httpx.get(url, headers=headers, timeout=TIMEOUT, follow_redirects=True)
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                try:
                    data = resp.json()
                except Exception:
                    data = yaml.safe_load(resp.text)
                if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                    return data
        except (httpx.RequestError, Exception):
            continue
    return None


# ---------------------------------------------------------------------------
# Parser – Swagger 2 & OpenAPI 3
# ---------------------------------------------------------------------------

def _extract_param(p: dict, root: dict) -> Param:
    """Convert an OpenAPI/Swagger parameter dict -> Param."""
    resolved = _deep_resolve(p, root)
    loc_raw = resolved.get("in", "query")
    loc_map = {"path": "path", "query": "query", "header": "header", "body": "body",
               "cookie": "query"}  # cookie -> treat as query
    return Param(
        name=resolved.get("name", "unknown"),
        **{"in": loc_map.get(loc_raw, "query")},
        type=resolved.get("schema", {}).get("type", resolved.get("type", "string")),
        required=resolved.get("required", False),
    )


def _has_security(operation: dict, global_security: list | None) -> bool:
    """Return True if the operation requires auth."""
    sec = operation.get("security", global_security)
    if sec is None:
        return False
    # Empty security array [] means NO auth required
    if isinstance(sec, list) and len(sec) == 0:
        return False
    # Non-empty list with at least one non-empty dict -> auth required
    for item in sec:
        if isinstance(item, dict) and len(item) > 0:
            return True
    return False


def _parse_spec(spec: dict, target_url: str, auth_header: str | None) -> Registry:
    """Parse an OpenAPI 3.x or Swagger 2.0 spec into a Registry."""
    is_v3 = "openapi" in spec
    global_security = spec.get("security")
    routes: list[Route] = []

    paths = spec.get("paths", {})
    for path_str, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        # path-level parameters
        path_params_raw = path_item.get("parameters", [])
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            operation = path_item.get(method)
            if not operation or not isinstance(operation, dict):
                continue

            # Merge path-level + operation-level parameters
            op_params_raw = operation.get("parameters", [])
            all_params_raw = path_params_raw + op_params_raw
            params = [_extract_param(p, spec) for p in all_params_raw]

            # Request body
            request_body_schema: dict | None = None
            if is_v3:
                rb = operation.get("requestBody", {})
                if isinstance(rb, dict):
                    rb = _deep_resolve(rb, spec)
                    content = rb.get("content", {})
                    for ct in ("application/json", "application/x-www-form-urlencoded", "*/*"):
                        if ct in content:
                            schema = content[ct].get("schema", {})
                            request_body_schema = _deep_resolve(schema, spec)
                            break
            else:
                # Swagger 2 – body parameter
                for p in all_params_raw:
                    rp = _deep_resolve(p, spec)
                    if rp.get("in") == "body":
                        request_body_schema = _deep_resolve(rp.get("schema", {}), spec)
                        break

            # Response schemas
            response_schemas: dict[str, dict] = {}
            responses = operation.get("responses", {})
            for status, resp_obj in responses.items():
                if not isinstance(resp_obj, dict):
                    continue
                resp_resolved = _deep_resolve(resp_obj, spec)
                if is_v3:
                    content = resp_resolved.get("content", {})
                    for ct in ("application/json", "*/*"):
                        if ct in content:
                            response_schemas[str(status)] = _deep_resolve(
                                content[ct].get("schema", {}), spec)
                            break
                else:
                    s = resp_resolved.get("schema")
                    if s:
                        response_schemas[str(status)] = _deep_resolve(s, spec)

            route = Route(
                method=method.upper(),
                path=path_str,
                params=params,
                request_body_schema=request_body_schema,
                response_schemas=response_schemas,
                auth_required=_has_security(operation, global_security),
            )
            routes.append(route)

    return Registry(
        target_url=target_url,
        source="openapi",
        auth_header=auth_header,
        routes=routes,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover(
    target_url: str,
    spec_path: str | None = None,
    auth_header: str | None = None,
) -> Registry:
    """Discover API endpoints from an OpenAPI/Swagger spec.

    Args:
        target_url: Base URL of the target API.
        spec_path: Path to a local spec file or URL. If None, probes common paths.
        auth_header: Optional auth header string, e.g. "Authorization: Bearer xxx".

    Returns:
        Registry with discovered routes.

    Raises:
        SystemExit: If no spec can be found.
    """
    t0 = time.perf_counter()

    if spec_path:
        spec = _load_spec_from_path(spec_path)
    else:
        spec = _probe_spec(target_url, auth_header)
        if spec is None:
            import sys
            print(f"ERROR: Tidak dapat menemukan OpenAPI/Swagger spec di {target_url}")
            print("  Gunakan --spec <path> untuk memberikan path spec secara manual.")
            sys.exit(1)

    registry = _parse_spec(spec, target_url, auth_header)
    elapsed = time.perf_counter() - t0
    print(f"[discovery] Parsed {len(registry.routes)} routes in {elapsed:.2f}s")

    if len(registry.routes) == 0:
        import sys
        print("ERROR: Spec ditemukan tetapi tidak ada endpoint (routes kosong). Audit berhenti.")
        sys.exit(1)

    return registry
