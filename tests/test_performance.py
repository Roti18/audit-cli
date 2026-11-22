"""Unit test untuk Performance Driver (k6)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from audit.drivers.performance import (
    ResourceMonitor,
    find_k6,
    generate_k6_script,
    parse_k6_summary,
    restart_target_container,
    run_k6_profile,
    run_performance,
)
from audit.schemas import Param, ParamLocation, Registry, Route


@pytest.fixture
def sample_registry() -> Registry:
    return Registry(
        target_url="http://localhost:3000",
        auth_header="Bearer dummy_token_123",
        routes=[
            Route(
                method="GET",
                path="/api/Products/{id}",
                params=[Param(name="id", location=ParamLocation.path, required=True)],
            ),
            Route(
                method="GET",
                path="/rest/products/search",
                params=[Param(name="q", location=ParamLocation.query)],
            ),
            Route(
                method="POST",
                path="/api/Feedbacks",
                params=[],
            ),
            # Rute berbahaya / destruktif yang harus diabaikan dalam load test
            Route(
                method="DELETE",
                path="/api/Products/{id}",
                params=[Param(name="id", location=ParamLocation.path, required=True)],
            ),
            Route(
                method="POST",
                path="/rest/user/change-password",
                params=[],
            ),
        ],
    )


def test_generate_k6_script(sample_registry: Registry, tmp_path: Path):
    script_path = tmp_path / "k6_test_script.js"
    res_path = generate_k6_script(sample_registry, script_path)

    assert res_path.exists()
    content = res_path.read_text(encoding="utf-8")

    # Pastikan struktur dasar JavaScript k6
    assert "import http from 'k6/http';" in content
    assert "import { check, sleep } from 'k6';" in content
    assert "export default function" in content
    assert "http://localhost:3000" in content
    assert "Bearer dummy_token_123" in content

    # Pastikan rute aman disertakan dan path parameter dinormalisasi
    assert "/api/Products/1" in content
    assert "/rest/products/search" in content

    # Pastikan rute destruktif TIDAK disertakan
    assert "change-password" not in content
    assert "DELETE" not in content


def test_parse_k6_summary():
    mock_summary = {
        "metrics": {
            "http_reqs": {
                "values": {
                    "count": 500,
                    "rate": 50.0,
                }
            },
            "http_req_duration": {
                "values": {
                    "avg": 85.5,
                    "min": 10.0,
                    "med": 75.0,
                    "max": 350.0,
                    "p(90)": 120.0,
                    "p(95)": 150.0,
                    "p(99)": 210.0,
                }
            },
            "http_req_failed": {
                "values": {
                    "rate": 0.02,  # 2% error rate
                }
            },
        }
    }

    mock_resource = {
        "cpu_pct_avg": 25.0,
        "cpu_pct_peak": 40.0,
        "mem_pct_avg": 30.0,
        "mem_pct_peak": 45.0,
    }

    parsed = parse_k6_summary(mock_summary, resource_summary=mock_resource, L=500.0)

    assert parsed["total_requests"] == 500
    assert parsed["rps"] == 50.0
    assert parsed["latency_avg_ms"] == 85.5
    assert parsed["latency_p95_ms"] == 150.0
    assert parsed["latency_p99_ms"] == 210.0
    assert parsed["error_rate"] == 0.02
    assert parsed["cpu_pct_peak"] == 40.0
    assert parsed["mem_pct_peak"] == 45.0

    # Pastikan scorecard breakdown dihitung
    sc = parsed["scorecard"]
    assert sc["error_rate"] == 0.02
    assert sc["p_error"] == 98.0
    # Platency: ((500 - 85.5) / 500) * 100 = 82.9
    assert round(sc["p_latency"], 1) == 82.9
    # Presource: 100 - max(40, 45) = 55.0
    assert sc["p_resource"] == 55.0
    # Pperf = 0.5 * 98 + 0.3 * 82.9 + 0.2 * 55 = 49 + 24.87 + 11 = 84.87
    assert 84.0 <= parsed["pperf"] <= 86.0


def test_resource_monitor_host():
    monitor = ResourceMonitor(container_name=None, interval=0.1)
    cpu, mem = monitor._sample_host()
    assert isinstance(cpu, float)
    assert isinstance(mem, float)
    assert 0.0 <= cpu <= 100.0
    assert 0.0 <= mem <= 100.0


def test_restart_target_container_offline():
    # Jika docker container tidak ada, harus return False dan tidak crash
    res = restart_target_container("non_existent_container_xyz", "http://127.0.0.1:9999", timeout=1)
    assert res is False


def test_run_k6_profile_mock(tmp_path: Path):
    script_file = tmp_path / "dummy_script.js"
    script_file.write_text("export default function() {}", encoding="utf-8")

    # Mock find_k6 dan subprocess.run
    with patch("audit.drivers.performance.find_k6", return_value="k6"), \
         patch("audit.drivers.performance.restart_target_container", return_value=True), \
         patch("subprocess.run") as mock_subproc:

        # Buat mock summary k6
        summary_file = tmp_path / "k6_typical.json"
        summary_content = {
            "metrics": {
                "http_reqs": {"values": {"count": 100, "rate": 10.0}},
                "http_req_duration": {"values": {"avg": 50.0, "p(95)": 80.0, "p(99)": 100.0}},
                "http_req_failed": {"values": {"rate": 0.0}},
            }
        }
        summary_file.write_text(json.dumps(summary_content), encoding="utf-8")

        mock_subproc.return_value = MagicMock(returncode=0, stdout="", stderr="")

        res = run_k6_profile(
            profile_name="typical",
            script_path=script_file,
            out_dir=tmp_path,
            target_url="http://localhost:3000",
            quick=True,
        )

        assert res["profile"] == "typical"
        assert res["rps"] == 10.0
        assert res["latency_avg_ms"] == 50.0
        assert res["error_rate"] == 0.0
        assert res["pperf"] > 0


def test_run_performance_missing_k6(sample_registry: Registry, tmp_path: Path):
    with patch("audit.drivers.performance.find_k6", return_value=None):
        res = run_performance(sample_registry, run_dir=tmp_path)
        assert res["status"] == "SKIPPED"
        assert res["evaluated"] is False
        assert "tidak ditemukan" in res["error"]
        assert (tmp_path / "performance.json").exists()
