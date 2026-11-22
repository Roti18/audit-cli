"""Menjalankan mock Clean API dan mengeksekusi Audit Kesiapan Produksi Jalur Sukses (PASSED)."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import httpx

project_root = Path(__file__).resolve().parent.parent

# 1. Jalankan clean_api
print("[Clean API Runner] Memulai server clean-api di port 5000...")
proc = subprocess.Popen(
    [sys.executable, "-m", "audit.clean_api"],
    cwd=str(project_root),
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

try:
    # Tunggu server siap
    ready = False
    for _ in range(10):
        try:
            r = httpx.get("http://localhost:5000/health", timeout=1.0)
            if r.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.5)

    if not ready:
        print("[Clean API Runner] Gagal menghubungkan ke clean-api.")
        sys.exit(1)

    print("[Clean API Runner] Server clean-api siap! Memulai audit...")

    # 2. Jalankan audit CLI
    cmd = [
        sys.executable, "-m", "audit.cli", "run",
        "http://localhost:5000",
        "--spec", "data/openapi_clean_api.yaml",
        "--run-id", "clean_api",
        "--quick",
        "--scale", "0.1",
        "--skip-security",
        "--skip-waf",
    ]
    res = subprocess.run(cmd, cwd=str(project_root))
    print(f"\n[Clean API Runner] Audit selesai dengan exit code: {res.returncode}")

finally:
    print("[Clean API Runner] Menghentikan clean-api server...")
    proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except Exception:
        proc.kill()
