"""Unit test untuk Report Generator (JSON, CSV, HTML Standalone)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit.report.generator import (
    generate_report,
    get_machine_specs,
    get_tool_versions,
)


def test_get_machine_specs():
    specs = get_machine_specs()
    assert "os" in specs
    assert "cpu" in specs
    assert "ram" in specs
    assert "python" in specs


def test_get_tool_versions():
    tools = get_tool_versions()
    assert "k6_version" in tools
    assert "mitmproxy_version" in tools
    assert "docker_version" in tools


def test_generate_report_complete(tmp_path: Path):
    # Buat mock file hasil audit
    reg_data = {"target_url": "http://localhost:3000", "routes": [{"method": "GET", "path": "/api/test"}]}
    (tmp_path / "registry.json").write_text(json.dumps(reg_data), encoding="utf-8")

    func_data = {"passed": 10, "total": 10, "pass_rate": 1.0, "test_cases": []}
    (tmp_path / "functional.json").write_text(json.dumps(func_data), encoding="utf-8")

    union_data = [
        {
            "tool": "zap+nuclei",
            "name": "SQL Injection",
            "cwe": "CWE-89",
            "route": "/rest/user/login",
            "method": "POST",
            "param": "email",
            "severity": "Critical",
            "cvss": 9.8,
        },
        {
            "tool": "zap",
            "name": "X-Content-Type-Options Missing",
            "cwe": "CWE-16",
            "route": "/api/Products",
            "method": "GET",
            "param": "",
            "severity": "Low",
            "cvss": 3.1,
        },
    ]
    (tmp_path / "union.json").write_text(json.dumps(union_data), encoding="utf-8")

    perf_data = {
        "target_url": "http://localhost:3000",
        "aggregate_pperf": 85.5,
        "profiles": {
            "typical": {"target_vus": 100, "rps": 150.0, "latency_avg_ms": 45.0, "latency_p95_ms": 75.0, "latency_p99_ms": 95.0, "error_rate": 0.0, "cpu_pct_peak": 30.0, "mem_pct_peak": 40.0, "pperf": 89.0},
            "peak": {"target_vus": 500, "rps": 350.0, "latency_avg_ms": 90.0, "latency_p95_ms": 140.0, "latency_p99_ms": 180.0, "error_rate": 0.0, "cpu_pct_peak": 50.0, "mem_pct_peak": 55.0, "pperf": 82.0},
        },
    }
    (tmp_path / "performance.json").write_text(json.dumps(perf_data), encoding="utf-8")

    waf_data = {
        "evaluated": True,
        "total_test_requests": 50,
        "normal_requests_count": 25,
        "attack_requests_count": 25,
        "realtime_metrics": {"accuracy": 0.94, "precision": 0.92, "recall": 0.96, "f1": 0.94, "fpr": 0.04},
        "baseline_accuracy": 0.60,
        "hold_out_accuracy_csic": 0.78,
    }
    (tmp_path / "waf.json").write_text(json.dumps(waf_data), encoding="utf-8")

    # Generate Report
    report = generate_report(run_dir=tmp_path, out_dir=tmp_path)

    assert report is not None
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.csv").exists()
    assert (tmp_path / "metrics.csv").exists()
    assert (tmp_path / "report.html").exists()

    # Periksa isi report.json
    rep_json = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert rep_json["scorecard"]["decision"] == "REJECTED"  # Ada Critical finding
    assert rep_json["scorecard"]["kill_switch"] is True

    # Periksa isi report.csv
    csv_text = (tmp_path / "report.csv").read_text(encoding="utf-8")
    assert "SQL Injection" in csv_text
    assert "CWE-89" in csv_text

    # Periksa isi metrics.csv
    m_csv = (tmp_path / "metrics.csv").read_text(encoding="utf-8")
    assert "TYPICAL" in m_csv
    assert "PEAK" in m_csv

    # Periksa isi report.html
    html_text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "REJECTED" in html_text
    assert "KILL SWITCH DIPICU" in html_text
    assert "UPRI Scorecard" in html_text
    assert "bar-fill" in html_text
    assert "report.html" in html_text


def test_generate_report_graceful_missing_data(tmp_path: Path):
    # Uji saat data kosong / minimal (hanya registry), generator tidak boleh crash
    reg_data = {"target_url": "http://localhost:5000", "routes": []}
    (tmp_path / "registry.json").write_text(json.dumps(reg_data), encoding="utf-8")

    report = generate_report(run_dir=tmp_path, out_dir=tmp_path)
    assert report is not None
    assert (tmp_path / "report.html").exists()

    html_text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "INCOMPLETE" in html_text or "PASSED" in html_text
    assert "tidak tersedia" in html_text
