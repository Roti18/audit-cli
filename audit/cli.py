"""CLI entry point – Typer application.

Subcommands:
  audit discover <url>    – Parse OpenAPI spec dan buat registry.json
  audit functional        – Jalankan functional test cases dari registry
  audit run <url>         – Full audit pipeline (akan dikembangkan di blok berikutnya)
"""

from __future__ import annotations

import json
import shutil
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import typer

from audit.schemas import Finding, Registry, Route, Severity, load_json, save_json

app = typer.Typer(
    name="audit",
    help="Framework Audit Kesiapan Produksi API berbasis CLI.",
    add_completion=False,
)


def _ensure_local(url: str, allow_remote: bool) -> None:
    """Tolak URL non-lokal kecuali --allow-remote."""
    if allow_remote:
        return
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ""
    local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
    if host not in local_hosts and not host.startswith("192.168.") and not host.startswith("10."):
        typer.echo(f"ERROR: Target {url} bukan lokal. Gunakan --allow-remote untuk mengizinkan.")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------
@app.command()
def discover(
    url: str = typer.Argument(..., help="Base URL target API, misal http://localhost:3000"),
    spec: Optional[str] = typer.Option(None, "--spec", help="Path/URL ke file OpenAPI spec"),
    header: Optional[str] = typer.Option(None, "--header", help='Auth header, misal "Authorization: Bearer xxx"'),
    out: str = typer.Option("results/default", "--out", help="Direktori output"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
) -> None:
    """Discover API endpoints dari OpenAPI/Swagger spec."""
    _ensure_local(url, allow_remote)

    from audit.discovery.openapi import discover as _discover

    registry = _discover(url, spec_path=spec, auth_header=header)
    out_path = Path(out) / "registry.json"
    save_json(registry, out_path)
    typer.echo(f"Registry disimpan ke {out_path} ({len(registry.routes)} routes)")


# ---------------------------------------------------------------------------
# functional
# ---------------------------------------------------------------------------
@app.command()
def functional(
    registry_path: str = typer.Option(
        "results/default/registry.json", "--registry",
        help="Path ke registry.json",
    ),
    run_id: str = typer.Option("default", "--run-id", help="Run identifier"),
    out: Optional[str] = typer.Option(None, "--out", help="Direktori output (default: results/<run_id>)"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
) -> None:
    """Jalankan functional test cases dari registry."""
    from audit.drivers.functional import run_functional

    reg = load_json(Registry, registry_path)
    _ensure_local(reg.target_url, allow_remote)

    result = run_functional(reg, run_id=run_id, out_dir=out)

    # Exit code berdasarkan pass rate
    if result.pass_rate < 1.0:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# security
# ---------------------------------------------------------------------------
@app.command()
def security(
    registry_path: str = typer.Option(
        "results/default/registry.json", "--registry",
        help="Path ke registry.json",
    ),
    scanner2: str = typer.Option("nuclei", "--scanner2", help="Scanner kedua: arachni|nuclei"),
    out: str = typer.Option("results/default", "--out", help="Direktori output"),
    max_minutes: int = typer.Option(30, "--max-minutes", help="Batas waktu pemindaian per scanner (menit)"),
    zap_url: str = typer.Option("http://localhost:8080", "--zap-url", help="URL ZAP daemon API"),
    api_key: str = typer.Option("changeme", "--api-key", help="API key ZAP"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
    parallel: bool = typer.Option(True, "--parallel/--no-parallel", help="Jalankan scanner secara paralel"),
) -> None:
    """Jalankan security driver (OWASP ZAP + scanner kedua) terhadap registry."""
    from audit.drivers.security import run_security

    reg = load_json(Registry, registry_path)
    _ensure_local(reg.target_url, allow_remote)

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)

    typer.echo(f"[security] Memulai audit keamanan untuk {reg.target_url}...")
    typer.echo(f"[security] Output & log ditulis ke: {out_path}")

    summary = run_security(
        registry=reg,
        run_dir=out_path,
        scanner2=scanner2,
        parallel=parallel,
        max_minutes=max_minutes,
        api_key=api_key,
        zap_url=zap_url,
    )

    typer.echo(f"[security] Selesai!")
    typer.echo(f"  ZAP findings: {summary['zap_findings_count']}")
    typer.echo(f"  Scanner2 ({scanner2}) findings: {summary['scanner2_findings_count']}")
    typer.echo(f"  Detail log tersimpan di: {out_path / 'security.log'}")


# ---------------------------------------------------------------------------
# train-waf
# ---------------------------------------------------------------------------
@app.command(name="train-waf")
def train_waf_command(
    data_dir: str = typer.Option("data/csic", "--data", help="Direktori dataset CSIC 2010"),
    model_out: str = typer.Option("audit/mlwaf/model.joblib", "--out", help="Path output file model joblib"),
    results_dir: str = typer.Option("results", "--results", help="Direktori output laporan dan grafik"),
) -> None:
    """Latih model ML-WAF Decision Tree dengan tahapan metodologi CRISP-DM."""
    from audit.mlwaf.train import train_mlwaf

    typer.echo("[train-waf] Memulai proses training CRISP-DM...")
    train_mlwaf(data_dir=data_dir, model_output=model_out, results_dir=results_dir)


# ---------------------------------------------------------------------------
# security-report
# ---------------------------------------------------------------------------
@app.command(name="security-report")
def security_report_command(
    run_dir: str = typer.Option("results/run1", "--run-dir", help="Direktori hasil audit"),
    ground_truth: str = typer.Option("data/ground_truth_juiceshop.json", "--ground-truth", help="Path ke ground truth JSON"),
    scanner2: str = typer.Option("nuclei", "--scanner2", help="Nama scanner kedua (arachni|nuclei)"),
    match_param: bool = typer.Option(False, "--match-param", help="Cocokkan juga nama parameter secara persis"),
) -> None:
    """Buat Union List dan cetak evaluasi metrik (Precision, Recall, F1) vs Ground Truth."""
    import json
    from audit.schemas import Finding
    from audit.security.metrics import compute_security_metrics
    from audit.security.union import save_union, union_findings

    p_run = Path(run_dir)
    zap_file = p_run / "findings_zap.json"
    s2_file = p_run / "findings_scanner2.json"
    union_file = p_run / "union.json"

    zap_findings = [Finding.model_validate(f) for f in json.loads(zap_file.read_text(encoding="utf-8"))] if zap_file.exists() else []
    s2_findings = [Finding.model_validate(f) for f in json.loads(s2_file.read_text(encoding="utf-8"))] if s2_file.exists() else []

    # Buat Union List
    union_list, intersection_list = union_findings(zap_findings, s2_findings, scanner2_name=scanner2)
    save_union(union_list, union_file)
    typer.echo(f"[security-report] Union List disimpan ke: {union_file} ({len(union_list)} temuan, {len(intersection_list)} irisan)")

    # Hitung metrik
    metrics = compute_security_metrics(
        zap_findings=zap_findings,
        scanner2_findings=s2_findings,
        union_findings=union_list,
        ground_truth_path=ground_truth,
        scanner2_name=scanner2,
        out_dir=p_run,
        match_param=match_param,
    )

    typer.echo("\n======================================================================")
    typer.echo("               EVALUASI METRIK DETEKSI KEAMANAN DAST")
    typer.echo("======================================================================")
    import pandas as pd
    csv_file = p_run / "security_metrics.csv"
    if csv_file.exists():
        df = pd.read_csv(csv_file)
        typer.echo(df.to_string(index=False))

    rec = metrics["recall_improvement"]
    typer.echo("\n----------------------------------------------------------------------")
    typer.echo("ANALISIS PENINGKATAN RECALL (UNION LIST vs SINGLE SCANNER):")
    typer.echo(f"  - Pemindai Tunggal Terbaik : {rec['best_single_scanner']} ({rec['best_single_recall'] * 100:.2f}%)")
    typer.echo(f"  - Recall Union List        : {rec['union_recall'] * 100:.2f}%")
    typer.echo(f"  - Peningkatan Poin %       : +{rec['percentage_points']['vs_best_single']} pp")
    typer.echo(f"  - Peningkatan Relatif      : +{rec['relative_percent']['vs_best_single']}%")

    status_str = "[PASS]" if rec["target_passed_relative"] or rec["target_passed_percentage_points"] else "[FAIL]"
    typer.echo(f"  - Status Target (>= 15%)   : {status_str}")
    typer.echo(f"\n{metrics['disclaimer']}")
    typer.echo("======================================================================\n")


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------
@app.command(name="score")
def score_command(
    run_dir: str = typer.Option("results/run1", "--run-dir", help="Direktori hasil audit"),
    findings_file: Optional[str] = typer.Option(None, "--findings", help="Path file union.json atau findings.json"),
    perf_file: Optional[str] = typer.Option(None, "--perf-file", help="Path file performance.json"),
    allow_skip_perf: bool = typer.Option(False, "--allow-skip-perf", help="Hitung UPRI meskipun data performa tidak lengkap"),
) -> None:
    """Hitung Skor Kesiapan Produksi (UPRI), evaluasi Kill Switch, dan cetak Scorecard."""
    import json
    from audit.schemas import Finding
    from audit.scorecard.engine import build_scorecard

    p_run = Path(run_dir)

    # 1. Cari file temuan keamanan
    f_path = Path(findings_file) if findings_file else (p_run / "union.json")
    if not f_path.exists():
        f_path = p_run / "findings_zap.json"

    findings: list[Finding] = []
    if f_path.exists():
        findings = [Finding.model_validate(f) for f in json.loads(f_path.read_text(encoding="utf-8"))]
        typer.echo(f"[score] Memuat {len(findings)} temuan dari {f_path.name}")
    else:
        typer.echo(f"[score] Peringatan: Berkas temuan keamanan tidak ditemukan di {p_run}")

    # 2. Cari file performa
    p_perf_path = Path(perf_file) if perf_file else (p_run / "performance.json")
    perf_profiles = None
    if p_perf_path.exists():
        raw_perf = json.loads(p_perf_path.read_text(encoding="utf-8"))
        perf_profiles = raw_perf.get("profiles", raw_perf)
        typer.echo(f"[score] Memuat data performa dari {p_perf_path.name}")

    # 3. Hitung Scorecard
    scorecard = build_scorecard(
        run_id=p_run.name,
        findings=findings,
        profiles=perf_profiles,
        out_dir=p_run,
        allow_skip_perf=allow_skip_perf,
    )

    typer.echo("\n======================================================================")
    typer.echo("                    API PRODUCTION READINESS SCORECARD")
    typer.echo("======================================================================")
    typer.echo(f"Run ID        : {scorecard.run_id}")
    typer.echo(f"Ssec (Security)    : {scorecard.ssec:.2f} / 100.00")
    typer.echo(f"Pperf (Performance): {scorecard.pperf:.2f} / 100.00")
    typer.echo(f"UPRI Final         : {scorecard.upri:.2f} / 100.00")
    typer.echo(f"Kill Switch Aktif  : {'YA' if scorecard.kill_switch else 'TIDAK'}")

    if scorecard.kill_switch and scorecard.kill_reasons:
        typer.echo("\nAlasan Kill Switch Dipicu:")
        for r in scorecard.kill_reasons:
            typer.echo(f"  [!] {r}")

    typer.echo("----------------------------------------------------------------------")
    typer.echo(f"KEPUTUSAN AKHIR : {scorecard.decision} (Exit Code: {scorecard.exit_code})")
    typer.echo("----------------------------------------------------------------------")
    typer.echo(f"Berkas hasil disimpan ke: {p_run / 'scorecard.json'}\n")

    raise typer.Exit(code=scorecard.exit_code)


# ---------------------------------------------------------------------------
# waf (Active Defense Verifier)
# ---------------------------------------------------------------------------
@app.command(name="waf")
def waf_command(
    registry_path: str = typer.Option(
        "results/default/registry.json", "--registry",
        help="Path ke registry.json",
    ),
    out: str = typer.Option("results/default", "--out", help="Direktori output run"),
    proxy_port: int = typer.Option(8082, "--proxy-port", help="Port reverse proxy mitmproxy WAF"),
    model_path: str = typer.Option("audit/mlwaf/model.joblib", "--model", help="Path ke model joblib"),
    target_url: Optional[str] = typer.Option(None, "--target-url", help="Override base target URL"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
) -> None:
    """Verifikasi Active Defense ML-WAF secara real-time via mitmproxy reverse proxy."""
    from audit.drivers.waf_verifier import run_waf_verifier

    reg = load_json(Registry, registry_path)
    target = target_url or reg.target_url
    _ensure_local(target, allow_remote)

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)

    typer.echo(f"[waf] Memulai verifikasi real-time ML-WAF terhadap {target}...")
    typer.echo(f"[waf] Proxy port: {proxy_port} | Model: {model_path}")

    res = run_waf_verifier(
        registry=reg,
        run_dir=out_path,
        proxy_port=proxy_port,
        model_path=model_path,
        target_url=target,
    )

    if not res.get("evaluated", True):
        typer.echo(f"[waf] Error: {res.get('error')}")
        raise typer.Exit(code=1)

    m = res.get("realtime_metrics", {})
    typer.echo("\n======================================================================")
    typer.echo("               HASIL EVALUASI REAL-TIME ACTIVE DEFENSE (ML-WAF)")
    typer.echo("======================================================================")
    typer.echo(f"Total Uji Request    : {res.get('total_test_requests')}")
    typer.echo(f"  - Request Normal   : {res.get('normal_requests_count')}")
    typer.echo(f"  - Request Serangan : {res.get('attack_requests_count')}")
    typer.echo("----------------------------------------------------------------------")
    typer.echo(f"Akurasi Real-Time    : {m.get('accuracy', 0.0) * 100:.2f}% (Target: >= 90%)")
    typer.echo(f"Precision            : {m.get('precision', 0.0) * 100:.2f}%")
    typer.echo(f"Recall               : {m.get('recall', 0.0) * 100:.2f}%")
    typer.echo(f"F1-Score             : {m.get('f1', 0.0) * 100:.2f}%")
    typer.echo(f"False Positive Rate  : {m.get('fpr', 0.0) * 100:.2f}%")
    typer.echo("----------------------------------------------------------------------")
    typer.echo(f"Baseline Keyword Acc : {res.get('baseline_accuracy', 0.0) * 100:.2f}%")
    if res.get("hold_out_accuracy_csic") is not None:
        typer.echo(f"Hold-out CSIC Acc    : {res.get('hold_out_accuracy_csic') * 100:.2f}%")
    status_str = "[PASS]" if res.get("target_passed") else "[FAIL]"
    typer.echo(f"Status Target Akurasi: {status_str}")
    typer.echo(f"\n{res.get('note')}")
    typer.echo("======================================================================\n")


# ---------------------------------------------------------------------------
# perf (Performance Driver)
# ---------------------------------------------------------------------------
@app.command(name="perf")
def perf_command(
    registry_path: str = typer.Option(
        "results/default/registry.json", "--registry",
        help="Path ke registry.json",
    ),
    out: str = typer.Option("results/default", "--out", help="Direktori output run"),
    profiles: str = typer.Option(
        "typical,peak,stress,spike", "--profiles",
        help="Daftar profil pengujian dipisahkan koma (typical,peak,stress,spike)",
    ),
    scale: float = typer.Option(1.0, "--scale", help="Faktor skala beban VU (misal 0.1 untuk laptop spek rendah)"),
    quick: bool = typer.Option(False, "--quick", help="Mode cepat (durasi pengujian dipersingkat untuk dry-run)"),
    container: str = typer.Option("juice-shop", "--container", help="Nama kontainer Docker target untuk restart dan monitoring"),
    target_url: Optional[str] = typer.Option(None, "--target-url", help="Override base target URL"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
) -> None:
    """Jalankan Performance Driver (k6) dengan profil Typical, Peak, Stress, dan Spike."""
    from audit.drivers.performance import run_performance

    reg = load_json(Registry, registry_path)
    target = target_url or reg.target_url
    _ensure_local(target, allow_remote)

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)

    prof_list = [p.strip().lower() for p in profiles.split(",") if p.strip()]

    typer.echo(f"[perf] Memulai pengujian performa k6 terhadap {target}...")
    typer.echo(f"[perf] Profil: {', '.join(prof_list)} | Scale: {scale} | Quick: {quick}")

    def _progress(msg: str) -> None:
        typer.echo(f"  [>] {msg}")

    result = run_performance(
        registry=reg,
        run_dir=out_path,
        profiles=prof_list,
        scale=scale,
        quick=quick,
        container_name=container,
        target_url=target,
        progress_callback=_progress,
    )

    if not result.get("evaluated", True):
        typer.echo(f"[perf] Error/Skipped: {result.get('error')}")
        raise typer.Exit(code=1)

    typer.echo("\n=========================================================================================")
    typer.echo("                       RINGKASAN HASIL PENGUJIAN PERFORMA (k6)")
    typer.echo("=========================================================================================")
    import pandas as pd
    rows = []
    for prof_name, p_data in result.get("profiles", {}).items():
        rows.append({
            "Profil": prof_name.upper(),
            "VUs": p_data.get("target_vus", "-"),
            "RPS": p_data.get("rps", 0.0),
            "Avg Lat (ms)": p_data.get("latency_avg_ms", 0.0),
            "P95 (ms)": p_data.get("latency_p95_ms", 0.0),
            "P99 (ms)": p_data.get("latency_p99_ms", 0.0),
            "Error Rate": f"{p_data.get('error_rate', 0.0) * 100:.2f}%",
            "CPU Peak": f"{p_data.get('cpu_pct_peak', 0.0):.1f}%",
            "Mem Peak": f"{p_data.get('mem_pct_peak', 0.0):.1f}%",
            "Pperf": f"{p_data.get('pperf', 0.0):.2f}",
        })

    if rows:
        df = pd.DataFrame(rows)
        typer.echo(df.to_string(index=False))

    typer.echo("-----------------------------------------------------------------------------------------")
    typer.echo(f"AGGREGATE PPERF (Typical, Peak, Stress): {result.get('aggregate_pperf', 0.0):.2f} / 100.00")
    typer.echo(f"Berkas hasil disimpan ke: {out_path / 'performance.json'}\n")


# ---------------------------------------------------------------------------
# report (Regenerate reports from raw run artifacts)
# ---------------------------------------------------------------------------
@app.command(name="report")
def report_command(
    run_dir: str = typer.Option("results/default", "--run-dir", help="Direktori hasil audit mentah"),
    out: Optional[str] = typer.Option(None, "--out", help="Direktori output laporan (default: run_dir)"),
) -> None:
    """Regenerasi laporan (report.json, report.csv, metrics.csv, report.html) dari hasil mentah."""
    from audit.report.generator import generate_report

    p_run = Path(run_dir)
    p_out = Path(out) if out else p_run
    typer.echo(f"[report] Meregenerasi laporan dari {p_run} ke {p_out}...")
    generate_report(run_dir=p_run, out_dir=p_out)
    typer.echo(f"[report] Selesai!")
    typer.echo(f"  - JSON  : {p_out / 'report.json'}")
    typer.echo(f"  - CSV   : {p_out / 'report.csv'}")
    typer.echo(f"  - HTML  : {p_out / 'report.html'}\n")


# ---------------------------------------------------------------------------
# run (Full End-to-End Pipeline)
# ---------------------------------------------------------------------------
@app.command(name="run")
def run(
    url: str = typer.Argument(..., help="Base URL target API, misal http://localhost:3000"),
    spec: Optional[str] = typer.Option(None, "--spec", help="Path/URL ke file OpenAPI spec"),
    header: Optional[str] = typer.Option(None, "--header", help='Auth header, misal "Authorization: Bearer xxx"'),
    scanner2: str = typer.Option("arachni", "--scanner2", help="Scanner kedua: arachni|nuclei (default: arachni, otomatis fallback ke nuclei jika arachni unavailable)"),
    skip_functional: bool = typer.Option(False, "--skip-functional", help="Lewati functional testing"),
    skip_security: bool = typer.Option(False, "--skip-security", help="Lewati DAST security scan"),
    skip_waf: bool = typer.Option(False, "--skip-waf", help="Lewati verifikasi ML-WAF"),
    skip_perf: bool = typer.Option(False, "--skip-perf", help="Lewati pengujian performa k6"),
    scale: float = typer.Option(1.0, "--scale", help="Faktor skala beban VU k6 (misal 0.1 untuk laptop spec standar)"),
    quick: bool = typer.Option(False, "--quick", help="Mode cepat (durasi pengujian k6 & scan dipersingkat)"),
    max_scan_minutes: int = typer.Option(30, "--max-scan-minutes", help="Batas waktu pemindaian keamanan per scanner"),
    out: str = typer.Option("results", "--out", help="Direktori induk output"),
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Run identifier (default: auto-generate timestamp)"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
    reuse_run: Optional[str] = typer.Option(None, "--reuse-run", help="Gunakan hasil mentah scan dari run sebelumnya"),
    verbose: bool = typer.Option(False, "--verbose", help="Tampilkan detail log proses"),
) -> None:
    """Full End-to-End Audit Pipeline kesiapan produksi API."""
    import time
    start_total_time = time.time()

    # 1. Validasi Target
    _ensure_local(url, allow_remote)

    if run_id is None:
        run_id = datetime_id()

    p_run = Path(out) / run_id
    p_run.mkdir(parents=True, exist_ok=True)

    typer.echo("=========================================================================================")
    typer.echo(f"           AUDIT KESIAPAN PRODUKSI API - RUN ID: {run_id}")
    typer.echo(f"           Target: {url}")
    typer.echo("=========================================================================================")

    # Salin berkas jika reuse_run diberikan
    if reuse_run:
        p_reuse = Path(out) / reuse_run
        if p_reuse.exists() and p_reuse != p_run:
            typer.echo(f"[audit] Menyalin data mentah dari {p_reuse} ke {p_run}...")
            for f in p_reuse.glob("*.*"):
                if not (p_run / f.name).exists():
                    shutil.copy2(f, p_run / f.name)

    stages: dict[str, Any] = {}

    # -----------------------------------------------------------------------
    # TAHAP 1: DISCOVERY (Berhenti jika registri kosong -> Exit 4)
    # -----------------------------------------------------------------------
    typer.echo("\n[1/7] Menjalankan Target Discovery (OpenAPI/Swagger)...")
    t0 = time.time()
    from audit.discovery.openapi import discover as _discover

    registry = _discover(url, spec_path=spec, auth_header=header)
    if registry is None or len(registry.routes) == 0:
        typer.echo("\n[FATAL ERROR] Discovery gagal atau registri kosong. Target tidak memiliki rute OpenAPI yang valid.")
        typer.echo("Pastikan OpenAPI spec valid atau service target dapat diakses.")
        raise typer.Exit(code=4)

    save_json(registry, p_run / "registry.json")
    t_disc = round(time.time() - t0, 2)
    stages["discovery"] = {"status": "SUCCESS", "routes_count": len(registry.routes), "duration_s": t_disc}
    typer.echo(f"  [OK] Discovery sukses: {len(registry.routes)} endpoint ditemukan ({t_disc}s)")

    # -----------------------------------------------------------------------
    # TAHAP 2: FUNCTIONAL DRIVER
    # -----------------------------------------------------------------------
    typer.echo("\n[2/7] Menjalankan Uji Fungsional & Validasi Skema...")
    t0 = time.time()
    if skip_functional:
        stages["functional"] = {"status": "SKIPPED"}
        typer.echo("  [-] Uji fungsional dilewati (--skip-functional).")
    else:
        try:
            from audit.drivers.functional import run_functional
            func_res = run_functional(registry, run_id=run_id, out_dir=p_run)
            t_func = round(time.time() - t0, 2)
            stages["functional"] = {
                "status": "SUCCESS",
                "passed": func_res.passed,
                "total": func_res.total,
                "pass_rate": func_res.pass_rate,
                "duration_s": t_func,
            }
            typer.echo(f"  [OK] Functional: {func_res.passed}/{func_res.total} test cases lulus ({t_func}s)")
        except Exception as exc:
            typer.echo(f"  [!] Peringatan functional driver: {exc}")
            stages["functional"] = {"status": "ERROR", "error": str(exc)}

    # -----------------------------------------------------------------------
    # TAHAP 3: SECURITY DRIVER (DAST ZAP + Scanner2, Union List, Metrics)
    # -----------------------------------------------------------------------
    typer.echo(f"\n[3/7] Menjalankan Security Driver (OWASP ZAP + {scanner2})...")
    t0 = time.time()
    if skip_security:
        stages["security"] = {"status": "SKIPPED"}
        typer.echo("  [-] Security scan dilewati (--skip-security).")
    else:
        union_file = p_run / "union.json"
        if reuse_run and union_file.exists():
            typer.echo(f"  [OK] Memakai ulang hasil scan keamanan dari {reuse_run}")
            stages["security"] = {"status": "REUSED", "from": reuse_run}
        else:
            try:
                from audit.drivers.security import run_security
                from audit.security.metrics import compute_security_metrics
                from audit.security.union import save_union, union_findings

                sec_summary = run_security(
                    registry=registry,
                    run_dir=p_run,
                    scanner2=scanner2,
                    parallel=True,
                    max_minutes=max_scan_minutes,
                )

                # Muat hasil mentah scanner
                zap_file = p_run / "findings_zap.json"
                s2_file = p_run / "findings_scanner2.json"
                zap_findings = [Finding.model_validate(f) for f in json.loads(zap_file.read_text(encoding="utf-8"))] if zap_file.exists() else []
                s2_findings = [Finding.model_validate(f) for f in json.loads(s2_file.read_text(encoding="utf-8"))] if s2_file.exists() else []

                # Bangun Union List
                actual_s2_name = sec_summary.get("scanner2_used", scanner2)
                u_list, i_list = union_findings(zap_findings, s2_findings, scanner2_name=actual_s2_name)
                save_union(u_list, union_file)

                # Evaluasi Ground Truth jika ada
                gt_path = Path("data/ground_truth_clean_api.json") if ":5000" in url else Path("data/ground_truth_juiceshop.json")
                if gt_path.exists():
                    compute_security_metrics(
                        zap_findings=zap_findings,
                        scanner2_findings=s2_findings,
                        union_findings=u_list,
                        ground_truth_path=gt_path,
                        scanner2_name=actual_s2_name,
                        out_dir=p_run,
                    )

                t_sec = round(time.time() - t0, 2)
                stages["security"] = {"status": "SUCCESS", "union_count": len(u_list), "duration_s": t_sec}
                typer.echo(f"  [OK] Security: ZAP={len(zap_findings)}, {actual_s2_name}={len(s2_findings)} -> Union={len(u_list)} ({t_sec}s)")
            except Exception as exc:
                typer.echo(f"  [!] Peringatan security driver: {exc}")
                stages["security"] = {"status": "ERROR", "error": str(exc)}

    # -----------------------------------------------------------------------
    # TAHAP 4: ACTIVE DEFENSE VERIFIER (ML-WAF mitmproxy)
    # -----------------------------------------------------------------------
    typer.echo("\n[4/7] Menjalankan Verifikasi Active Defense (ML-WAF)...")
    t0 = time.time()
    if skip_waf:
        stages["waf"] = {"status": "SKIPPED"}
        typer.echo("  [-] Verifikasi ML-WAF dilewati (--skip-waf).")
    else:
        try:
            from audit.drivers.waf_verifier import run_waf_verifier
            waf_res = run_waf_verifier(
                registry=registry,
                run_dir=p_run,
                proxy_port=8082,
                target_url=url,
            )
            t_waf = round(time.time() - t0, 2)
            acc = waf_res.get("realtime_metrics", {}).get("accuracy", 0.0)
            stages["waf"] = {"status": "SUCCESS" if waf_res.get("evaluated") else "SKIPPED", "accuracy": acc, "duration_s": t_waf}
            typer.echo(f"  [OK] ML-WAF: Akurasi={acc * 100:.2f}%, FPR={waf_res.get('realtime_metrics', {}).get('fpr', 0.0) * 100:.2f}% ({t_waf}s)")
        except Exception as exc:
            typer.echo(f"  [!] Peringatan ML-WAF verifier: {exc}")
            stages["waf"] = {"status": "ERROR", "error": str(exc)}

    # -----------------------------------------------------------------------
    # TAHAP 5: TARGET RESET & HEALTHCHECK
    # -----------------------------------------------------------------------
    typer.echo("\n[5/7] Menyiapkan Target Baseline (Reset & Healthcheck)...")
    t0 = time.time()
    target_container = "clean-api" if ":5000" in url else "juice-shop"
    if not skip_perf:
        from audit.drivers.performance import restart_target_container
        restart_target_container(container_name=target_container, target_url=url, timeout=10)
        t_reset = round(time.time() - t0, 2)
        stages["target_reset"] = {"status": "SUCCESS", "container": target_container, "duration_s": t_reset}
        typer.echo(f"  [OK] Baseline siap ({t_reset}s)")
    else:
        typer.echo("  [-] Target reset dilewati.")

    # -----------------------------------------------------------------------
    # TAHAP 6: PERFORMANCE DRIVER (k6)
    # -----------------------------------------------------------------------
    typer.echo("\n[6/7] Menjalankan Performance Driver (k6 Load & Stress Testing)...")
    t0 = time.time()
    if skip_perf:
        stages["performance"] = {"status": "SKIPPED"}
        typer.echo("  [-] Performance driver dilewati (--skip-perf).")
    else:
        perf_file = p_run / "performance.json"
        if reuse_run and perf_file.exists():
            typer.echo(f"  [OK] Memakai ulang hasil performa dari {reuse_run}")
            stages["performance"] = {"status": "REUSED", "from": reuse_run}
        else:
            try:
                from audit.drivers.performance import run_performance
                scale_val = scale if scale != 1.0 else (0.1 if quick else 1.0)

                def _p_cb(m: str) -> None:
                    if verbose:
                        typer.echo(f"    [k6] {m}")

                perf_res = run_performance(
                    registry=registry,
                    run_dir=p_run,
                    scale=scale_val,
                    quick=quick,
                    container_name=target_container,
                    target_url=url,
                    progress_callback=_p_cb,
                )
                t_perf = round(time.time() - t0, 2)
                p_pperf = perf_res.get("aggregate_pperf", 0.0)
                stages["performance"] = {"status": "SUCCESS" if perf_res.get("evaluated") else "SKIPPED", "pperf": p_pperf, "duration_s": t_perf}
                typer.echo(f"  [OK] Performance selesai: Pperf Agregat={p_pperf:.2f} ({t_perf}s)")
            except Exception as exc:
                typer.echo(f"  [!] Peringatan performance driver: {exc}")
                stages["performance"] = {"status": "ERROR", "error": str(exc)}

    # -----------------------------------------------------------------------
    # TAHAP 7: SCORECARD ENGINE & REPORT GENERATION
    # -----------------------------------------------------------------------
    typer.echo("\n[7/7] Menghitung Skor Kesiapan Produksi (UPRI) & Menghasilkan Laporan...")
    from audit.scorecard.engine import build_scorecard
    from audit.report.generator import generate_report

    # Muat temuan keamanan
    findings: list[Finding] = []
    union_path = p_run / "union.json"
    if union_path.exists():
        try:
            findings = [Finding.model_validate(f) for f in json.loads(union_path.read_text(encoding="utf-8"))]
        except Exception:
            pass

    # Muat profil performa
    perf_profiles = None
    perf_path = p_run / "performance.json"
    if perf_path.exists():
        try:
            p_data = json.loads(perf_path.read_text(encoding="utf-8"))
            perf_profiles = p_data.get("profiles", p_data)
        except Exception:
            pass

    # Hitung Scorecard
    allow_skip = skip_perf or (perf_profiles is None)
    scorecard = build_scorecard(
        run_id=run_id,
        findings=findings,
        profiles=perf_profiles,
        out_dir=p_run,
        allow_skip_perf=allow_skip,
    )

    total_duration = round(time.time() - start_total_time, 2)
    run_meta = {
        "run_id": run_id,
        "target_url": url,
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": total_duration,
        "scanner2": scanner2,
        "stages": stages,
    }
    (p_run / "run_metadata.json").write_text(json.dumps(run_meta, indent=2), encoding="utf-8")

    # Generate Semua Format Laporan
    generate_report(run_dir=p_run, out_dir=p_run, custom_metadata=run_meta)

    # -----------------------------------------------------------------------
    # EXECUTIVE SUMMARY BANNER
    # -----------------------------------------------------------------------
    typer.echo("\n=========================================================================================")
    typer.echo(f"                           HASIL AKHIR AUDIT: {scorecard.decision}")
    typer.echo("=========================================================================================")
    typer.echo(f"  - Target URL           : {url}")
    typer.echo(f"  - Total Durasi Audit   : {total_duration} detik")
    typer.echo(f"  - Ssec (Keamanan)      : {scorecard.ssec:.2f} / 100.00")
    typer.echo(f"  - Pperf (Performa)     : {scorecard.pperf:.2f} / 100.00")
    typer.echo(f"  - UPRI Final           : {scorecard.upri:.2f} / 100.00")
    typer.echo(f"  - Kill Switch Dipicu   : {'YA' if scorecard.kill_switch else 'TIDAK'}")

    if scorecard.kill_switch and scorecard.kill_reasons:
        typer.echo("\n  [ALASAN KILL SWITCH MEMBATALKAN RILIS]:")
        for kr in scorecard.kill_reasons:
            typer.echo(f"    * {kr}")

    typer.echo("-----------------------------------------------------------------------------------------")
    typer.echo(f"  KEPUTUSAN RILIS PRODUKSI: {scorecard.decision} (Exit Code: {scorecard.exit_code})")
    typer.echo(f"  Berkas Laporan Lengkap  : {p_run / 'report.html'}")
    typer.echo("=========================================================================================\n")

    raise typer.Exit(code=scorecard.exit_code)


def datetime_id() -> str:
    """Generate a short run ID from timestamp."""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def main() -> None:
    """Dispatcher entry point: mendukung `audit <url>` dan `audit <subcommand>`."""
    if len(sys.argv) > 1:
        first = sys.argv[1]
        known = {
            "discover", "functional", "security", "train-waf",
            "security-report", "score", "waf", "perf", "report", "run",
            "--help", "-h",
        }
        if first not in known and not first.startswith("-"):
            # Jika argumen pertama adalah target URL, sisipkan perintah 'run'
            sys.argv.insert(1, "run")
    app()


# ---------------------------------------------------------------------------
# Entry point for `python -m audit.cli`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
