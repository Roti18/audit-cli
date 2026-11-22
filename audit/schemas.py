"""Pydantic data schemas – kontrak data framework audit-cli.

Semua model di sini adalah Single Source of Truth untuk pertukaran data
antar modul (discovery, drivers, scorecard, report).
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ParamLocation(str, Enum):
    path = "path"
    query = "query"
    header = "header"
    body = "body"


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


# ---------------------------------------------------------------------------
# Route & Registry
# ---------------------------------------------------------------------------

class Param(BaseModel):
    name: str
    location: ParamLocation = Field(alias="in")
    type: str = "string"
    required: bool = False

    model_config = {"populate_by_name": True}


class Route(BaseModel):
    method: str
    path: str
    params: list[Param] = Field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    response_schemas: dict[str, dict[str, Any]] = Field(default_factory=dict)
    auth_required: bool = False


class Registry(BaseModel):
    target_url: str
    source: str = "openapi"
    auth_header: str | None = None
    routes: list[Route] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Finding (security driver output)
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    tool: str
    name: str
    cwe: str | None = None
    route: str
    method: str
    param: str | None = None
    severity: Severity
    cvss: float | None = None
    evidence: str | None = None


# ---------------------------------------------------------------------------
# Functional Driver output
# ---------------------------------------------------------------------------

class FunctionalTestCase(BaseModel):
    id: str
    route: str
    method: str
    passed: bool
    expected: str
    actual_status: int | None = None
    detail: str = ""


class FunctionalResult(BaseModel):
    run_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    test_cases: list[FunctionalTestCase] = Field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    pass_rate: float = 0.0


# ---------------------------------------------------------------------------
# Performance Driver output (placeholder for Blok 2+)
# ---------------------------------------------------------------------------

class PerformanceProfile(BaseModel):
    profile: str  # typical | peak | stress | spike
    total_requests: int = 0
    error_count: int = 0
    error_rate: float = 0.0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    peak_cpu_pct: float = 0.0
    peak_mem_pct: float = 0.0


class PerformanceResult(BaseModel):
    run_id: str
    profiles: list[PerformanceProfile] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scorecard (placeholder for Blok 2+)
# ---------------------------------------------------------------------------

class Scorecard(BaseModel):
    run_id: str
    ssec: float = 0.0
    pperf: float = 0.0
    upri: float = 0.0
    kill_switch: bool = False
    kill_reasons: list[str] = Field(default_factory=list)
    decision: str = "REJECTED"
    exit_code: int = 2


# ---------------------------------------------------------------------------
# Helpers – save / load
# ---------------------------------------------------------------------------

def save_json(model: BaseModel, path: str | Path) -> Path:
    """Serialize a Pydantic model to a JSON file (by_alias to keep 'in')."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(model.model_dump_json(indent=2, by_alias=True), encoding="utf-8")
    return p


def load_json(model_cls: type[BaseModel], path: str | Path) -> BaseModel:
    """Deserialize a JSON file into a Pydantic model."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return model_cls.model_validate(data)
