"""Unit test untuk CLI Pipeline End-to-End (audit <url>)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from audit.cli import app, main
from audit.schemas import Param, ParamLocation, Registry, Route

runner = CliRunner()


@pytest.fixture
def mock_registry() -> Registry:
    return Registry(
        target_url="http://localhost:3000",
        routes=[
            Route(
                method="GET",
                path="/api/test",
                params=[],
            )
        ],
    )


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Framework Audit Kesiapan Produksi API" in result.output
    assert "run" in result.output
    assert "report" in result.output


def test_cli_empty_registry_exit_4(tmp_path: Path):
    # Discovery mengembalikan registri kosong -> exit code 4
    empty_reg = Registry(target_url="http://localhost:3000", routes=[])
    with patch("audit.discovery.openapi.discover", return_value=empty_reg):
        result = runner.invoke(app, ["run", "http://localhost:3000", "--out", str(tmp_path)])
        assert result.exit_code == 4
        assert "FATAL ERROR" in result.output
        assert "registri kosong" in result.output


def test_cli_pipeline_success_mock(mock_registry: Registry, tmp_path: Path):
    def _mock_perf_side_effect(*args, **kwargs):
        run_dir = Path(kwargs.get("run_dir") or (args[1] if len(args) > 1 else tmp_path / "test_pass"))
        data = {
            "evaluated": True,
            "aggregate_pperf": 95.0,
            "profiles": {
                "typical": {"target_vus": 10, "latency_avg_ms": 20.0, "error_rate": 0.0, "cpu_pct_peak": 10.0, "mem_pct_peak": 15.0, "pperf": 96.0},
                "peak": {"target_vus": 50, "latency_avg_ms": 30.0, "error_rate": 0.0, "cpu_pct_peak": 20.0, "mem_pct_peak": 25.0, "pperf": 94.0},
                "stress": {"target_vus": 100, "latency_avg_ms": 40.0, "error_rate": 0.0, "cpu_pct_peak": 30.0, "mem_pct_peak": 35.0, "pperf": 92.0},
            },
        }
        (run_dir / "performance.json").write_text(json.dumps(data), encoding="utf-8")
        return data

    with patch("audit.discovery.openapi.discover", return_value=mock_registry), \
         patch("audit.drivers.functional.run_functional", return_value=MagicMock(passed=5, total=5, pass_rate=1.0)), \
         patch("audit.drivers.security.run_security", return_value={"zap_findings_count": 0, "scanner2_findings_count": 0, "scanner2_used": "nuclei"}), \
         patch("audit.drivers.waf_verifier.run_waf_verifier", return_value={"evaluated": True, "realtime_metrics": {"accuracy": 0.95, "fpr": 0.02}}), \
         patch("audit.drivers.performance.run_performance", side_effect=_mock_perf_side_effect):

        result = runner.invoke(app, [
            "run", "http://localhost:3000",
            "--out", str(tmp_path),
            "--run-id", "test_pass",
            "--quick",
        ])

        assert result.exit_code == 0
        assert "PASSED" in result.output
        assert (tmp_path / "test_pass" / "report.html").exists()
        assert (tmp_path / "test_pass" / "report.json").exists()


def test_cli_pipeline_rejected_by_kill_switch_mock(mock_registry: Registry, tmp_path: Path):
    run_dir = tmp_path / "test_reject"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Buat temuan Critical
    crit_findings = [{
        "tool": "zap",
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "route": "/api/login",
        "method": "POST",
        "param": "user",
        "severity": "Critical",
        "cvss": 9.8,
    }]
    (run_dir / "union.json").write_text(json.dumps(crit_findings), encoding="utf-8")

    with patch("audit.discovery.openapi.discover", return_value=mock_registry), \
         patch("audit.drivers.functional.run_functional", return_value=MagicMock(passed=0, total=0, pass_rate=1.0)), \
         patch("audit.drivers.security.run_security", return_value={"scanner2_used": "nuclei"}), \
         patch("audit.drivers.waf_verifier.run_waf_verifier", return_value={"evaluated": False}), \
         patch("audit.drivers.performance.run_performance", return_value={"evaluated": True, "aggregate_pperf": 80.0}):

        result = runner.invoke(app, [
            "run", "http://localhost:3000",
            "--out", str(tmp_path),
            "--run-id", "test_reject",
            "--skip-perf",
            "--reuse-run", "test_reject",
        ])

        assert result.exit_code == 2
        assert "REJECTED" in result.output
        assert "KILL SWITCH" in result.output


def test_cli_report_command(tmp_path: Path):
    # Test `audit report --run-dir ...`
    run_dir = tmp_path / "mock_run"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "registry.json").write_text(json.dumps({"target_url": "http://localhost:3000", "routes": []}), encoding="utf-8")

    result = runner.invoke(app, ["report", "--run-dir", str(run_dir)])
    assert result.exit_code == 0
    assert "Meregenerasi laporan" in result.output
    assert (run_dir / "report.html").exists()


def test_cli_dispatcher_main():
    # Test bahwa main() menyisipkan 'run' jika argumen pertama adalah URL
    with patch("sys.argv", ["audit", "http://localhost:3000", "--help"]):
        try:
            main()
        except SystemExit as exc:
            assert exc.code == 0
