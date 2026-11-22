"""Tests for security/union.py and security/metrics.py – Union List and Metrics Evaluator."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from audit.schemas import Finding, Severity
from audit.security.metrics import (
    compute_security_metrics,
    evaluate_tool_performance,
    match_finding_to_gt,
)
from audit.security.union import union_findings


def _make_f(tool: str, name: str, cwe: str, route: str, severity: Severity, param: str | None = None, method: str = "GET") -> Finding:
    return Finding(
        tool=tool,
        name=name,
        cwe=cwe,
        route=route,
        method=method,
        param=param,
        severity=severity,
    )


class TestUnionList:
    def test_union_deduplication_and_severity_resolution(self):
        # ZAP menemukan SQLi di /rest/products/search dengan severity Medium
        zap_findings = [
            _make_f("zap", "SQLi ZAP", "CWE-89", "/rest/products/search", Severity.medium, param="q"),
            _make_f("zap", "Info Disclosure", "CWE-200", "/rest/admin/application-version", Severity.low),
        ]
        # Nuclei menemukan SQLi yang sama tetapi severity High, plus XSS
        nuclei_findings = [
            _make_f("nuclei", "SQLi Nuclei", "CWE-89", "/rest/products/search", Severity.high, param="q"),
            _make_f("nuclei", "XSS Nuclei", "CWE-79", "/api/Feedbacks", Severity.high, param="comment", method="POST"),
        ]

        union_list, intersection_list = union_findings(zap_findings, nuclei_findings, scanner2_name="nuclei")

        # 3 temuan unik di Union: SQLi (merged), Info Disclosure (ZAP), XSS (Nuclei)
        assert len(union_list) == 3
        # 1 temuan di Intersection: SQLi
        assert len(intersection_list) == 1

        sqli_merged = [f for f in union_list if f.route == "/rest/products/search"][0]
        assert sqli_merged.tool == "zap+nuclei"
        assert sqli_merged.severity == Severity.high  # Mengambil severity tertinggi
        assert sqli_merged.cwe == "CWE-89"

    def test_union_deterministic_sorting(self):
        f_low = _make_f("zap", "Low Vuln", "CWE-200", "/b", Severity.low)
        f_crit = _make_f("zap", "Critical Vuln", "CWE-89", "/a", Severity.critical)
        f_med = _make_f("nuclei", "Medium Vuln", "CWE-79", "/c", Severity.medium)

        union_list, _ = union_findings([f_low, f_crit], [f_med])
        # Harus terurut: Critical -> Medium -> Low
        assert union_list[0].severity == Severity.critical
        assert union_list[1].severity == Severity.medium
        assert union_list[2].severity == Severity.low


class TestMetricsCalculation:
    @pytest.fixture
    def sample_gt(self):
        return [
            {"id": "GT-01", "cwe": "CWE-89", "route": "/rest/user/login", "method": "POST", "param": "email"},
            {"id": "GT-02", "cwe": "CWE-89", "route": "/rest/products/search", "method": "GET", "param": "q"},
            {"id": "GT-03", "cwe": "CWE-79", "route": "/rest/products/search", "method": "GET", "param": "q"},
            {"id": "GT-04", "cwe": "CWE-22", "route": "/ftp", "method": "GET", "param": "file"},
        ]

    def test_match_finding_to_gt(self, sample_gt):
        f_match = _make_f("zap", "SQLi", "CWE-89", "/rest/user/login", Severity.critical, method="POST")
        assert match_finding_to_gt(f_match, sample_gt[0]) is True

        f_wrong_cwe = _make_f("zap", "XSS", "CWE-79", "/rest/user/login", Severity.medium, method="POST")
        assert match_finding_to_gt(f_wrong_cwe, sample_gt[0]) is False

        f_wrong_route = _make_f("zap", "SQLi", "CWE-89", "/api/other", Severity.high, method="POST")
        assert match_finding_to_gt(f_wrong_route, sample_gt[0]) is False

    def test_evaluate_tool_performance(self, sample_gt):
        # Tool menemukan 2 dari 4 GT (TP=2, FN=2) dan 1 temuan non-GT (FP=1)
        findings = [
            _make_f("zap", "SQLi Login", "CWE-89", "/rest/user/login", Severity.critical, method="POST"),
            _make_f("zap", "SQLi Search", "CWE-89", "/rest/products/search", Severity.high, method="GET"),
            _make_f("zap", "Random Alert", "CWE-200", "/unknown", Severity.low),
        ]
        res = evaluate_tool_performance(findings, sample_gt)
        assert res["tp"] == 2
        assert res["fn"] == 2
        assert res["fp"] == 1
        assert res["recall"] == 0.5   # 2/4
        assert res["precision"] == round(2 / 3, 4)  # 2/3 = 0.6667

    def test_compute_security_metrics_recall_improvement(self, tmp_path):
        gt_file = tmp_path / "gt.json"
        gt_data = [
            {"id": "GT-01", "cwe": "CWE-89", "route": "/rest/user/login", "method": "POST", "param": "email"},
            {"id": "GT-02", "cwe": "CWE-89", "route": "/rest/products/search", "method": "GET", "param": "q"},
            {"id": "GT-03", "cwe": "CWE-79", "route": "/api/Feedbacks", "method": "POST", "param": "comment"},
            {"id": "GT-04", "cwe": "CWE-22", "route": "/ftp", "method": "GET", "param": "file"},
        ]
        gt_file.write_text(json.dumps(gt_data), encoding="utf-8")

        # ZAP mendeteksi GT-01 dan GT-02 (Recall = 2/4 = 50%)
        zap = [
            _make_f("zap", "SQLi 1", "CWE-89", "/rest/user/login", Severity.critical, method="POST"),
            _make_f("zap", "SQLi 2", "CWE-89", "/rest/products/search", Severity.high, method="GET"),
        ]
        # Scanner2 mendeteksi GT-02 dan GT-03 (Recall = 2/4 = 50%)
        s2 = [
            _make_f("nuclei", "SQLi 2", "CWE-89", "/rest/products/search", Severity.high, method="GET"),
            _make_f("nuclei", "XSS 3", "CWE-79", "/api/Feedbacks", Severity.high, method="POST"),
        ]
        # Union mendeteksi GT-01, GT-02, GT-03 (Recall = 3/4 = 75%)
        union, _ = union_findings(zap, s2, scanner2_name="nuclei")

        metrics = compute_security_metrics(
            zap_findings=zap,
            scanner2_findings=s2,
            union_findings=union,
            ground_truth_path=gt_file,
            out_dir=tmp_path,
        )

        assert metrics["evaluations"]["zap"]["recall"] == 0.5
        assert metrics["evaluations"]["scanner2"]["recall"] == 0.5
        assert metrics["evaluations"]["union"]["recall"] == 0.75

        # Poin persentase: 75% - 50% = +25.0 pp (Target >= 15 pp tercapai)
        assert metrics["recall_improvement"]["percentage_points"]["vs_best_single"] == 25.0
        assert metrics["recall_improvement"]["target_passed_percentage_points"] is True

        # Peningkatan relatif: (75% - 50%) / 50% = +50.0% (Target >= 15% tercapai)
        assert metrics["recall_improvement"]["relative_percent"]["vs_best_single"] == 50.0
        assert metrics["recall_improvement"]["target_passed_relative"] is True
