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
