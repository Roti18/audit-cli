"""CLI entry point – Typer application.

Subcommands:
  audit discover <url>    – Parse OpenAPI spec dan buat registry.json
  audit functional        – Jalankan functional test cases dari registry
  audit run <url>         – Full audit pipeline (akan dikembangkan di blok berikutnya)
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Optional

import typer

from audit.schemas import Registry, load_json, save_json

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
# run (full pipeline)
# ---------------------------------------------------------------------------
@app.command()
def run(
    url: str = typer.Argument(..., help="Base URL target API"),
    spec: Optional[str] = typer.Option(None, "--spec", help="Path/URL ke file OpenAPI spec"),
    header: Optional[str] = typer.Option(None, "--header", help="Auth header"),
    run_id: str = typer.Option(None, "--run-id", help="Run identifier (default: auto-generate)"),
    allow_remote: bool = typer.Option(False, "--allow-remote", help="Izinkan target non-lokal"),
    scanner2: str = typer.Option("nuclei", "--scanner2", help="Scanner kedua: nuclei|arachni"),
) -> None:
    """Full audit pipeline (Blok 2+ akan melengkapi)."""
    if run_id is None:
        run_id = datetime_id()
    _ensure_local(url, allow_remote)

    out_dir = str(Path("results") / run_id)

    # Step 1: Discovery
    from audit.discovery.openapi import discover as _discover
    registry = _discover(url, spec_path=spec, auth_header=header)
    save_json(registry, Path(out_dir) / "registry.json")
    typer.echo(f"[run] Registry: {len(registry.routes)} routes")

    # Step 2: Functional
    from audit.drivers.functional import run_functional
    func_result = run_functional(registry, run_id=run_id, out_dir=out_dir)

    typer.echo(f"\n[run] Functional: {func_result.passed}/{func_result.total} passed")

    # Step 3: Security
    from audit.drivers.security import run_security
    typer.echo(f"\n[run] Menjalankan Security Driver (ZAP + {scanner2})...")
    sec_summary = run_security(
        registry=registry,
        run_dir=out_dir,
        scanner2=scanner2,
        parallel=True,
        max_minutes=5,
    )
    typer.echo(f"[run] Security: ZAP={sec_summary['zap_findings_count']} findings, {scanner2}={sec_summary['scanner2_findings_count']} findings")
    typer.echo(f"[run] Output dir: {out_dir}")
    typer.echo("[run] Performance driver & Scorecard akan tersedia di Blok 3+.")


def datetime_id() -> str:
    """Generate a short run ID from timestamp."""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# Entry point for `python -m audit.cli`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app()
