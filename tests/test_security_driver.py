"""Tests for drivers/security.py – Orkestrasi keamanan, output files, dan fault tolerance."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from audit.drivers.security import run_security, run_zap, run_scanner2
from audit.schemas import Param, Registry, Route


@pytest.fixture
def dummy_registry():
    routes = [
        Route(
            method="GET",
            path="/api/Products/{id}",
            params=[Param(name="id", **{"in": "path"}, type="integer", required=True)],
        ),
        Route(
            method="GET",
            path="/rest/products/search",
            params=[Param(name="q", **{"in": "query"}, type="string", required=False)],
        ),
    ]
    return Registry(target_url="http://localhost:3000", routes=routes)


class TestSecurityDriverFaultTolerance:
    def test_run_zap_unreachable_target(self, dummy_registry, tmp_path):
        """ZAP offline tidak boleh crash dan harus menulis zap_raw.json & zap_attack_requests.json."""
        out_dir = tmp_path / "sec_test"
        result = run_zap(
            registry=dummy_registry,
            run_dir=out_dir,
            zap_url="http://127.0.0.1:59999",  # Port mati
            max_minutes=1,
        )
        assert "error" in result
        assert (out_dir / "zap_raw.json").exists()
        assert (out_dir / "zap_attack_requests.json").exists()

        zap_raw = json.loads((out_dir / "zap_raw.json").read_text())
        assert "error" in zap_raw

    def test_run_scanner2_fallback_when_tool_absent(self, dummy_registry, tmp_path):
        """Scanner kedua harus menulis scanner2_raw.json tanpa crash."""
        out_dir = tmp_path / "sec_test2"
        result = run_scanner2(
            registry=dummy_registry,
            run_dir=out_dir,
            scanner="nuclei",
            max_minutes=1,
        )
        assert (out_dir / "scanner2_raw.json").exists()

    def test_run_security_full_pipeline_mock(self, dummy_registry, tmp_path):
        """run_security harus menghasilkan semua 5 file output dan log file."""
        out_dir = tmp_path / "run_sec_full"
        summary = run_security(
            registry=dummy_registry,
            run_dir=out_dir,
            scanner2="nuclei",
            parallel=True,
            max_minutes=1,
            zap_url="http://127.0.0.1:59999",
        )

        assert (out_dir / "zap_raw.json").exists()
        assert (out_dir / "scanner2_raw.json").exists()
        assert (out_dir / "findings_zap.json").exists()
        assert (out_dir / "findings_scanner2.json").exists()
        assert (out_dir / "zap_attack_requests.json").exists()
        assert (out_dir / "security.log").exists()

        assert summary["zap_findings_count"] >= 0
        assert summary["scanner2_findings_count"] >= 0
