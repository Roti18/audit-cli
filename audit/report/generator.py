"""Report Generator (JSON, HTML, CSV).

Mengumpulkan seluruh artefak hasil pengujian dari results/<run_id>/:
- report.json: gabungan metadata, functional, security union, metrics, waf, performance, scorecard.
- report.csv: tabel temuan Union (tool, severity, cwe, method, route, param).
- metrics.csv: metrik performa tiap profil (RPS, latensi P95/P99, error rate, CPU/Mem, Pperf).
- report.html: satu halaman mandiri (CSS inline, tanpa CDN), banner keputusan besar,
  skor UPRI, breakdown Ssec & Pperf, kill switch reasons, visual bar, dan metadata lingkungan.
"""

from __future__ import annotations

import base64
import csv
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import jinja2

from audit.schemas import Finding
from audit.scorecard.engine import build_scorecard

logger = logging.getLogger("audit.report")


def get_machine_specs() -> dict[str, str]:
    """Mengambil spesifikasi mesin host secara otomatis."""
    os_str = platform.platform()
    cpu_str = platform.processor() or "Unknown CPU"

    cpu_cores = os.cpu_count() or 1
    cpu_full = f"{cpu_str} ({cpu_cores} Logical Cores)"

    ram_str = "Unknown RAM"
    try:
        import psutil
        total_ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        ram_str = f"{total_ram_gb:.2f} GB"
    except Exception:
        pass

    return {
        "os": os_str,
        "cpu": cpu_full,
        "ram": ram_str,
        "python": sys.version.split()[0],
    }


def get_tool_versions() -> dict[str, str]:
    """Mengambil versi tool eksternal yang terpasang di host."""
    versions: dict[str, str] = {}

    # k6
    k6_bin = shutil.which("k6") or os.environ.get("K6_BIN")
    if not k6_bin and Path(r"C:\k6-v1.5.0-windows-amd64\k6.exe").exists():
        k6_bin = r"C:\k6-v1.5.0-windows-amd64\k6.exe"

    if k6_bin:
        try:
            res = subprocess.run([k6_bin, "version"], capture_output=True, text=True, timeout=3.0)
            if res.returncode == 0:
                versions["k6_version"] = res.stdout.strip().splitlines()[0]
        except Exception:
            versions["k6_version"] = "Terdeteksi (k6)"
    else:
        versions["k6_version"] = "Tidak Terpasang"

    # mitmdump
    try:
        venv_mitm = Path(sys.prefix) / "Scripts" / "mitmdump.exe"
        m_bin = str(venv_mitm) if venv_mitm.exists() else shutil.which("mitmdump")
        if m_bin:
            res = subprocess.run([m_bin, "--version"], capture_output=True, text=True, timeout=3.0)
            if res.returncode == 0:
                versions["mitmproxy_version"] = res.stdout.strip().splitlines()[0]
    except Exception:
        versions["mitmproxy_version"] = "Terpasang (mitmproxy)"

    # Docker
    docker_bin = shutil.which("docker")
    if docker_bin:
        try:
            res = subprocess.run([docker_bin, "--version"], capture_output=True, text=True, timeout=3.0)
            if res.returncode == 0:
                versions["docker_version"] = res.stdout.strip()
        except Exception:
            versions["docker_version"] = "Tersedia"
    else:
        versions["docker_version"] = "Tidak Terpasang"

    return versions


def _load_optional_json(path: Path) -> Any | None:
    """Membaca file JSON jika ada; jika tidak ada atau error, kembalikan None."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"Gagal memuat JSON dari {path}: {exc}")
        return None


def generate_report(
    run_dir: str | Path,
    out_dir: str | Path | None = None,
    custom_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Menghasilkan report.json, report.csv, metrics.csv, dan report.html dari berkas hasil run."""
    run_path = Path(run_dir)
    out_path = Path(out_dir) if out_dir else run_path
    out_path.mkdir(parents=True, exist_ok=True)

    logger.info(f"[Report Generator] Mengumpulkan data dari {run_path} ke {out_path}...")

    # 1. Muat seluruh berkas mentah
    meta_raw = _load_optional_json(run_path / "run_metadata.json") or {}
    reg_raw = _load_optional_json(run_path / "registry.json")
    func_raw = _load_optional_json(run_path / "functional.json")
    union_raw = _load_optional_json(run_path / "union.json") or []
    sec_metrics_raw = _load_optional_json(run_path / "security_metrics.json")
    waf_raw = _load_optional_json(run_path / "waf.json")
    perf_raw = _load_optional_json(run_path / "performance.json")
    score_raw = _load_optional_json(run_path / "scorecard.json")

    # 2. Sinkronkan Scorecard jika belum dihitung sebelumnya
    union_findings: list[Finding] = []
    if isinstance(union_raw, list):
        for item in union_raw:
            try:
                union_findings.append(Finding.model_validate(item))
            except Exception:
                pass

    if score_raw is None:
        perf_profiles = None
        if isinstance(perf_raw, dict):
            perf_profiles = perf_raw.get("profiles", perf_raw)
        try:
            sc_obj = build_scorecard(
                run_id=run_path.name,
                findings=union_findings,
                profiles=perf_profiles,
                out_dir=run_path,
                allow_skip_perf=True,
            )
            score_raw = json.loads(sc_obj.model_dump_json())
        except Exception as exc:
            logger.warning(f"Gagal menghitung scorecard otomatis: {exc}")

    # 3. Gabungkan Metadata Lingkungan
    env_info = get_machine_specs()
    env_info.update(get_tool_versions())

    run_id = (custom_metadata or {}).get("run_id") or meta_raw.get("run_id") or run_path.name
    target_url = (
        (custom_metadata or {}).get("target_url")
        or (reg_raw or {}).get("target_url")
        or (perf_raw or {}).get("target_url")
        or "http://localhost:3000"
    )

    metadata_consolidated = {
        "run_id": run_id,
        "timestamp": (custom_metadata or {}).get("timestamp") or meta_raw.get("timestamp") or datetime.now().isoformat(),
        "target_url": target_url,
        "duration_seconds": (custom_metadata or {}).get("duration_seconds") or meta_raw.get("duration_seconds", 0.0),
        "scanner2": (custom_metadata or {}).get("scanner2") or meta_raw.get("scanner2", "nuclei"),
        "stages": meta_raw.get("stages", {}),
        "env": env_info,
    }

    # 4. Bangun report.json
    report_data: dict[str, Any] = {
        "metadata": metadata_consolidated,
        "registry": {
            "total_routes": len(reg_raw.get("routes", [])) if reg_raw else 0,
            "target_url": target_url,
        },
        "functional": func_raw,
        "security": {
            "union_findings": [f.model_dump() for f in union_findings],
            "metrics": sec_metrics_raw,
        },
        "waf": waf_raw,
        "performance": perf_raw,
        "scorecard": score_raw,
    }

    report_json_path = out_path / "report.json"
    report_json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    logger.info(f"[Report Generator] report.json ditulis ke: {report_json_path}")

    # 5. Bangun report.csv (Tabel Temuan Union)
    report_csv_path = out_path / "report.csv"
    with open(report_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["tool", "severity", "cwe", "method", "route", "param", "cvss", "name"],
        )
        writer.writeheader()
        for finding in union_findings:
            writer.writerow({
                "tool": finding.tool,
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "cwe": finding.cwe or "",
                "method": finding.method,
                "route": finding.route,
                "param": finding.param or "",
                "cvss": finding.cvss or "",
                "name": finding.name,
            })
    logger.info(f"[Report Generator] report.csv ditulis ke: {report_csv_path}")

    # 6. Bangun metrics.csv (Metrik Performa Tiap Profil)
    metrics_csv_path = out_path / "metrics.csv"
    with open(metrics_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "profile", "vus", "rps", "latency_avg_ms", "latency_p95_ms",
                "latency_p99_ms", "error_rate", "cpu_pct_peak", "mem_pct_peak",
                "platency", "presource", "pperf",
            ],
        )
        writer.writeheader()
        if perf_raw and "profiles" in perf_raw and isinstance(perf_raw["profiles"], dict):
            for prof_name, p in perf_raw["profiles"].items():
                sc = p.get("scorecard", {})
                writer.writerow({
                    "profile": prof_name.upper(),
                    "vus": p.get("target_vus", ""),
                    "rps": p.get("rps", 0.0),
                    "latency_avg_ms": p.get("latency_avg_ms", 0.0),
                    "latency_p95_ms": p.get("latency_p95_ms", 0.0),
                    "latency_p99_ms": p.get("latency_p99_ms", 0.0),
                    "error_rate": p.get("error_rate", 0.0),
                    "cpu_pct_peak": p.get("cpu_pct_peak", 0.0),
                    "mem_pct_peak": p.get("mem_pct_peak", 0.0),
                    "platency": sc.get("p_latency", 0.0),
                    "presource": sc.get("p_resource", 0.0),
                    "pperf": p.get("pperf", 0.0),
                })
    logger.info(f"[Report Generator] metrics.csv ditulis ke: {metrics_csv_path}")

    # 7. Siapkan gambar WAF Confusion Matrix (Base64 Inline)
    waf_cm_b64 = None
    waf_png_path = run_path / "waf_confusion_matrix.png"
    if waf_png_path.exists():
        try:
            waf_cm_b64 = base64.b64encode(waf_png_path.read_bytes()).decode("utf-8")
        except Exception as exc:
            logger.warning(f"Gagal membaca berkas WAF PNG: {exc}")

    # 8. Render report.html via Jinja2
    template_dir = Path(__file__).resolve().parent / "templates"
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("report.html.j2")

    html_rendered = template.render(
        metadata=metadata_consolidated,
        registry=report_data["registry"],
        functional=func_raw,
        security=report_data["security"],
        waf=waf_raw,
        waf_cm_b64=waf_cm_b64,
        performance=perf_raw,
        scorecard=score_raw,
    )

    report_html_path = out_path / "report.html"
    report_html_path.write_text(html_rendered, encoding="utf-8")
    logger.info(f"[Report Generator] report.html (Standalone) ditulis ke: {report_html_path}")

    return report_data
