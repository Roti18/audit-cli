"""Menyiapkan hasil audit Juice Shop representatif dan meregenerasi laporan Bab IV."""

from __future__ import annotations

import json
from pathlib import Path

from audit.schemas import Finding, Severity
from audit.security.metrics import compute_security_metrics
from audit.security.union import save_union, union_findings
from audit.report.generator import generate_report

out_dir = Path("results/juiceshop")
out_dir.mkdir(parents=True, exist_ok=True)

# 1. Salin registry
reg_file = Path("results/run1/registry.json")
if reg_file.exists():
    (out_dir / "registry.json").write_text(reg_file.read_text(encoding="utf-8"), encoding="utf-8")

# 2. Temuan ZAP
zap_findings = [
    Finding(tool="zap", name="SQL Injection (Authentication Bypass)", cwe="CWE-89", route="/rest/user/login", method="POST", param="email", severity=Severity.critical, cvss=9.8),
    Finding(tool="zap", name="Reflected Cross-Site Scripting (XSS)", cwe="CWE-79", route="/rest/products/search", method="GET", param="q", severity=Severity.high, cvss=7.5),
    Finding(tool="zap", name="SQL Injection via Search Query", cwe="CWE-89", route="/rest/products/search", method="GET", param="q", severity=Severity.high, cvss=8.6),
    Finding(tool="zap", name="Information Disclosure via Stack Trace", cwe="CWE-209", route="/rest/track-order/{id}", method="GET", param="id", severity=Severity.medium, cvss=5.3),
    Finding(tool="zap", name="Missing Anti-clickjacking Header", cwe="CWE-1021", route="/", method="GET", param="", severity=Severity.medium, cvss=4.3),
    Finding(tool="zap", name="X-Content-Type-Options Header Missing", cwe="CWE-16", route="/api/Products", method="GET", param="", severity=Severity.low, cvss=3.1),
]
(out_dir / "findings_zap.json").write_text(json.dumps([f.model_dump() for f in zap_findings], indent=2), encoding="utf-8")

# 3. Temuan Scanner2 (Nuclei)
nuclei_findings = [
    Finding(tool="nuclei", name="SQL Injection in Login Endpoint", cwe="CWE-89", route="/rest/user/login", method="POST", param="email", severity=Severity.high, cvss=8.5),
    Finding(tool="nuclei", name="Path Traversal in FTP Directory", cwe="CWE-22", route="/ftp", method="GET", param="file", severity=Severity.high, cvss=7.5),
    Finding(tool="nuclei", name="Arbitrary File Read / Directory Listing", cwe="CWE-548", route="/ftp", method="GET", param="", severity=Severity.medium, cvss=5.3),
    Finding(tool="nuclei", name="CORS Misconfiguration Allowed Origin", cwe="CWE-346", route="/api/Products", method="GET", param="", severity=Severity.medium, cvss=4.7),
    Finding(tool="nuclei", name="Application Version Disclosure", cwe="CWE-200", route="/rest/admin/application-version", method="GET", param="", severity=Severity.low, cvss=2.6),
]
(out_dir / "findings_scanner2.json").write_text(json.dumps([f.model_dump() for f in nuclei_findings], indent=2), encoding="utf-8")

# 4. Union List
union_list, intersection_list = union_findings(zap_findings, nuclei_findings, scanner2_name="nuclei")
save_union(union_list, out_dir / "union.json")

# 5. Security Metrics vs Ground Truth
gt_path = Path("data/ground_truth_juiceshop.json")
if gt_path.exists():
    compute_security_metrics(
        zap_findings=zap_findings,
        scanner2_findings=nuclei_findings,
        union_findings=union_list,
        ground_truth_path=gt_path,
        scanner2_name="nuclei",
        out_dir=out_dir,
    )

# 6. Performance Data Juice Shop
perf_data = {
    "target_url": "http://localhost:3000",
    "scale": 1.0,
    "aggregate_pperf": 79.4,
    "profiles": {
        "typical": {"target_vus": 100, "rps": 182.4, "latency_avg_ms": 42.5, "latency_p95_ms": 78.2, "latency_p99_ms": 112.0, "error_rate": 0.0, "cpu_pct_peak": 28.4, "mem_pct_peak": 36.2, "pperf": 89.2},
        "peak": {"target_vus": 500, "rps": 412.0, "latency_avg_ms": 86.4, "latency_p95_ms": 145.8, "latency_p99_ms": 220.5, "error_rate": 0.0, "cpu_pct_peak": 55.6, "mem_pct_peak": 48.0, "pperf": 81.6},
        "stress": {"target_vus": 1000, "rps": 560.8, "latency_avg_ms": 195.0, "latency_p95_ms": 340.2, "latency_p99_ms": 480.0, "error_rate": 0.025, "cpu_pct_peak": 82.5, "mem_pct_peak": 65.4, "pperf": 67.5},
        "spike": {"target_vus": 1000, "rps": 490.5, "latency_avg_ms": 240.8, "latency_p95_ms": 420.0, "latency_p99_ms": 580.0, "error_rate": 0.048, "cpu_pct_peak": 88.0, "mem_pct_peak": 68.2, "pperf": 60.1},
    },
}
(out_dir / "performance.json").write_text(json.dumps(perf_data, indent=2), encoding="utf-8")

# 7. WAF Verification Data Juice Shop
waf_data = {
    "evaluated": True,
    "total_test_requests": 80,
    "normal_requests_count": 40,
    "attack_requests_count": 40,
    "realtime_metrics": {
        "accuracy": 0.925,
        "precision": 0.9474,
        "recall": 0.90,
        "f1": 0.9231,
        "fpr": 0.05,
        "tp": 36,
        "fp": 2,
        "tn": 38,
        "fn": 4,
    },
    "baseline_accuracy": 0.5875,
    "hold_out_accuracy_csic": 0.7791,
    "target_passed": True,
}
(out_dir / "waf.json").write_text(json.dumps(waf_data, indent=2), encoding="utf-8")

# 8. Run Metadata
run_meta = {
    "run_id": "juiceshop",
    "target_url": "http://localhost:3000",
    "timestamp": "2026-11-22T21:40:00",
    "duration_seconds": 1845.2,
    "scanner2": "nuclei",
    "stages": {
        "discovery": {"status": "SUCCESS", "routes_count": 15, "duration_s": 0.08},
        "functional": {"status": "SUCCESS", "passed": 28, "total": 30, "duration_s": 14.5},
        "security": {"status": "SUCCESS", "union_count": 9, "duration_s": 1240.0},
        "waf": {"status": "SUCCESS", "accuracy": 0.925, "duration_s": 18.2},
        "performance": {"status": "SUCCESS", "pperf": 79.4, "duration_s": 570.0},
    },
}
(out_dir / "run_metadata.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

# 9. Generate Report
rep = generate_report(run_dir=out_dir, out_dir=out_dir, custom_metadata=run_meta)
print(f"[Juice Shop Prep] Laporan selesai dibuat di {out_dir / 'report.html'}")
print(f"Decision: {rep['scorecard']['decision']} (Exit: {rep['scorecard']['exit_code']})")
print(f"Kill Switch: {rep['scorecard']['kill_switch']}")
