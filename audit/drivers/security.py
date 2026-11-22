"""Security driver: Orkestrasi OWASP ZAP + Scanner kedua (Arachni / Nuclei).

Didesain untuk:
1. Berjalan di background dengan logging real-time ke security.log
2. Eksekusi paralel ZAP dan Scanner kedua via ThreadPoolExecutor
3. Toleran terhadap kegagalan salah satu scanner (tidak crash seluruh audit)
4. Menyimpan output mentah ke:
   - results/<run_id>/zap_raw.json
   - results/<run_id>/scanner2_raw.json
   - results/<run_id>/findings_zap.json
   - results/<run_id>/findings_scanner2.json
   - results/<run_id>/zap_attack_requests.json
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from audit.schemas import Finding, Registry, Route, save_json
from audit.security.normalizer import normalize_arachni, normalize_nuclei, normalize_zap

logger = logging.getLogger("audit.security")


# ---------------------------------------------------------------------------
# Helper: Logging setup
# ---------------------------------------------------------------------------
def setup_security_logger(log_file: Path) -> logging.Logger:
    """Setup logger ke konsol dan file security.log."""
    log = logging.getLogger(f"audit.security.{log_file.parent.name}")
    log.setLevel(logging.INFO)
    log.handlers.clear()

    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")

    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(formatter)
    log.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    log.addHandler(ch)

    return log


# ---------------------------------------------------------------------------
# ZAP Driver
# ---------------------------------------------------------------------------
def _seed_zap_sites_tree(registry: Registry, zap_url: str, api_key: str, log: logging.Logger) -> None:
    """Akses route-route di registry melalui proxy ZAP agar masuk ke Sites Tree."""
    log.info(f"[ZAP] Seeding sites tree dengan {len(registry.routes)} routes...")
    proxies = {"http://": zap_url, "https://": zap_url}
    headers = {}
    if registry.auth_header:
        k, _, v = registry.auth_header.partition(":")
        headers[k.strip()] = v.strip()

    try:
        with httpx.Client(proxies=proxies, timeout=5.0, verify=False) as client:
            for route in registry.routes[:20]:  # Batasi seed awal
                path = route.path
                for p in route.params:
                    if p.location == "path":
                        path = path.replace(f"{{{p.name}}}", "1")
                url = urljoin(registry.target_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    client.request(route.method, url, headers=headers)
                except Exception:
                    pass
    except Exception as exc:
        log.warning(f"[ZAP] Seeding via proxy gagal ({exc}), mencoba via accessUrl API...")
        # Fallback: gunakan core/action/accessUrl
        for route in registry.routes[:10]:
            try:
                path = route.path
                for p in route.params:
                    if p.location == "path":
                        path = path.replace(f"{{{p.name}}}", "1")
                target = urljoin(registry.target_url.rstrip("/") + "/", path.lstrip("/"))
                httpx.get(
                    f"{zap_url}/JSON/core/action/accessUrl/",
                    params={"apikey": api_key, "url": target},
                    timeout=3.0,
                )
            except Exception:
                pass


def _extract_zap_attack_requests(
    zap_url: str, api_key: str, target_url: str, log: logging.Logger
) -> list[dict[str, Any]]:
    """Ekstrak riwayat request HTTP dari ZAP active scan untuk dataset WAF."""
    log.info("[ZAP] Mengambil request history dari active scan...")
    attack_requests: list[dict[str, Any]] = []
    start = 0
    batch_size = 200

    while start < 2000:  # Batas maksimal 2000 requests
        try:
            resp = httpx.get(
                f"{zap_url}/JSON/core/view/messages/",
                params={
                    "apikey": api_key,
                    "baseurl": target_url,
                    "start": start,
                    "count": batch_size,
                },
                timeout=10.0,
            )
            if resp.status_code != 200:
                break
            data = resp.json()
            messages = data.get("messages", [])
            if not messages:
                break

            for msg in messages:
                raw_header = msg.get("requestHeader", "")
                raw_body = msg.get("requestBody", "")

                # Parse first line (METHOD URL PROTOCOL)
                lines = raw_header.splitlines()
                method = "GET"
                req_url = target_url
                headers: dict[str, str] = {}

                if lines:
                    first_line = lines[0].split(" ")
                    if len(first_line) >= 2:
                        method = first_line[0].upper()
                        req_url = first_line[1]

                    for line in lines[1:]:
                        if ":" in line:
                            hk, _, hv = line.partition(":")
                            headers[hk.strip()] = hv.strip()

                attack_requests.append({
                    "id": msg.get("id"),
                    "method": method,
                    "url": req_url,
                    "headers": headers,
                    "body": raw_body,
                    "label": "attack",
                    "rtt_ms": msg.get("rtt"),
                })

            start += len(messages)
            if len(messages) < batch_size:
                break
        except Exception as exc:
            log.warning(f"[ZAP] Error mengambil pesan ZAP: {exc}")
            break

    log.info(f"[ZAP] Berhasil mengekstrak {len(attack_requests)} attack requests.")
    return attack_requests


def run_zap(
    registry: Registry,
    run_dir: str | Path,
    api_key: str = "changeme",
    zap_url: str = "http://localhost:8080",
    max_minutes: int = 30,
    log: logging.Logger | None = None,
) -> dict[str, Any]:
    """Jalankan pemindaian kerentanan menggunakan OWASP ZAP via REST API."""
    if log is None:
        log = logger

    target_url = registry.target_url
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    zap_raw_file = run_path / "zap_raw.json"
    zap_attacks_file = run_path / "zap_attack_requests.json"

    log.info(f"[ZAP] Memulai pemindaian ke {target_url} (max {max_minutes}m)...")

    # 1. Cek konektivitas ke ZAP daemon
    try:
        ver_resp = httpx.get(
            f"{zap_url}/JSON/core/view/version/",
            params={"apikey": api_key},
            timeout=5.0,
        )
        if ver_resp.status_code != 200:
            raise ConnectionError(f"ZAP status HTTP {ver_resp.status_code}")
        zap_version = ver_resp.json().get("version", "unknown")
        log.info(f"[ZAP] Terhubung ke ZAP v{zap_version} di {zap_url}")
    except Exception as exc:
        err_msg = f"Tidak dapat terhubung ke ZAP di {zap_url}: {exc}"
        log.error(f"[ZAP] {err_msg}")
        err_payload = {"error": err_msg, "alerts": []}
        zap_raw_file.write_text(json.dumps(err_payload, indent=2), encoding="utf-8")
        zap_attacks_file.write_text(json.dumps([], indent=2), encoding="utf-8")
        return err_payload

    # 2. Seed routes ke Sites Tree
    _seed_zap_sites_tree(registry, zap_url, api_key, log)

    # 3. Buat Context untuk Target
    context_name = f"ctx_audit_{int(time.time())}"
    context_id = "1"
    try:
        ctx_resp = httpx.get(
            f"{zap_url}/JSON/context/action/newContext/",
            params={"apikey": api_key, "contextName": context_name},
            timeout=5.0,
        )
        if ctx_resp.status_code == 200:
            context_id = ctx_resp.json().get("contextId", "1")
            # Include target url regex
            regex = re.escape(target_url) + ".*"
            httpx.get(
                f"{zap_url}/JSON/context/action/includeInContext/",
                params={"apikey": api_key, "contextName": context_name, "regex": regex},
                timeout=5.0,
            )
            log.info(f"[ZAP] Context dibuat: {context_name} (ID: {context_id})")
    except Exception as exc:
        log.warning(f"[ZAP] Gagal konfigurasi context: {exc}")

    # 4. Spider Scan Terbatas
    try:
        log.info("[ZAP] Menjalankan spider scan...")
        spider_resp = httpx.get(
            f"{zap_url}/JSON/spider/action/scan/",
            params={
                "apikey": api_key,
                "url": target_url,
                "maxChildren": 5,
                "contextName": context_name,
            },
            timeout=5.0,
        )
        spider_id = spider_resp.json().get("scan", "0")
        spider_deadline = time.time() + 60  # max 1 menit untuk spider
        while time.time() < spider_deadline:
            st = httpx.get(
                f"{zap_url}/JSON/spider/view/status/",
                params={"apikey": api_key, "scanId": spider_id},
                timeout=5.0,
            ).json().get("status", "0")
            if int(st) >= 100:
                break
            time.sleep(2)
        log.info("[ZAP] Spider scan selesai.")
    except Exception as exc:
        log.warning(f"[ZAP] Spider scan dilewati/error: {exc}")

    # 5. Active Scan (Ascan) fokus: SQLi, XSS, CMDi, Path Traversal
    try:
        log.info("[ZAP] Memulai Active Scan (fokus: SQLi, XSS, CMDi, Traversal)...")
        ascan_resp = httpx.get(
            f"{zap_url}/JSON/ascan/action/scan/",
            params={
                "apikey": api_key,
                "url": target_url,
                "recurse": "true",
                "inScopeOnly": "true",
            },
            timeout=5.0,
        )
        ascan_id = ascan_resp.json().get("scan", "0")

        start_time = time.time()
        timeout_seconds = max_minutes * 60

        while True:
            elapsed = time.time() - start_time
            if elapsed >= timeout_seconds:
                log.info(f"[ZAP] Batas waktu {max_minutes}m tercapai, menghentikan ascan...")
                httpx.get(
                    f"{zap_url}/JSON/ascan/action/stop/",
                    params={"apikey": api_key, "scanId": ascan_id},
                    timeout=5.0,
                )
                break

            status_resp = httpx.get(
                f"{zap_url}/JSON/ascan/view/status/",
                params={"apikey": api_key, "scanId": ascan_id},
                timeout=5.0,
            )
            prog = status_resp.json().get("status", "0")
            log.info(f"[ZAP] Active Scan progress: {prog}% ({int(elapsed)}s)")
            if int(prog) >= 100:
                break
            time.sleep(5)

    except Exception as exc:
        log.error(f"[ZAP] Active scan error: {exc}")

    # 6. Ambil Alerts mentah
    raw_alerts_data: dict[str, Any] = {"alerts": []}
    try:
        alerts_resp = httpx.get(
            f"{zap_url}/JSON/core/view/alerts/",
            params={"apikey": api_key, "baseurl": target_url, "count": 5000},
            timeout=10.0,
        )
        if alerts_resp.status_code == 200:
            raw_alerts_data = alerts_resp.json()
            log.info(f"[ZAP] Pemindaian selesai: {len(raw_alerts_data.get('alerts', []))} alerts ditemukan.")
    except Exception as exc:
        log.error(f"[ZAP] Gagal mengambil alerts: {exc}")
        raw_alerts_data = {"error": str(exc), "alerts": []}

    # Simpan zap_raw.json
    zap_raw_file.write_text(json.dumps(raw_alerts_data, indent=2), encoding="utf-8")

    # 7. Ambil Request History untuk ML-WAF dataset
    attack_requests = _extract_zap_attack_requests(zap_url, api_key, target_url, log)
    zap_attacks_file.write_text(json.dumps(attack_requests, indent=2), encoding="utf-8")

    return raw_alerts_data


# ---------------------------------------------------------------------------
# Scanner Kedua (Arachni / Nuclei)
# ---------------------------------------------------------------------------
def _run_arachni(registry: Registry, run_dir: Path, max_minutes: int, log: logging.Logger) -> dict[str, Any]:
    """Jalankan Arachni via docker-compose / docker run."""
    log.info("[Scanner2: Arachni] Menyiapkan Arachni scan...")
    target_url = registry.target_url
    report_afr = "/tmp/audit_arachni.afr"
    report_json_container = "/tmp/audit_arachni.json"
    local_json = run_dir / "arachni_out.json"

    # Seed routes
    seed_urls = []
    for r in registry.routes[:10]:
        p = r.path
        for param in r.params:
            if param.location == "path":
                p = p.replace(f"{{{param.name}}}", "1")
        seed_urls.append(urljoin(target_url.rstrip("/") + "/", p.lstrip("/")))

    checks = "sql_injection*,xss*,os_cmd_injection*,path_traversal*"

    docker_bin = shutil.which("docker")
    if not docker_bin:
        err = "Docker executable tidak ditemukan di PATH host."
        log.warning(f"[Scanner2: Arachni] {err}")
        return {"error": err, "issues": []}

    try:
        # Jalankan scan
        cmd = [
            docker_bin, "run", "--rm",
            "--network", "audit-net",
            "arachni/arachni",
            f"--checks={checks}",
            f"--scope-include-subdomains",
            f"--timeout=00:{max_minutes:02d}:00",
            f"--report-save-path={report_afr}",
            target_url,
        ]
        log.info(f"[Scanner2: Arachni] Menjalankan: {' '.join(cmd[:6])} ...")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_minutes * 60 + 30)

        # Convert ke JSON
        conv_cmd = [
            docker_bin, "run", "--rm",
            "--network", "audit-net",
            "arachni/arachni",
            "arachni_reporter", report_afr,
            f"--reporter=json:outfile={report_json_container}",
        ]
        subprocess.run(conv_cmd, capture_output=True, text=True, timeout=60)

        # Ambil file JSON jika ada
        if local_json.exists():
            return json.loads(local_json.read_text(encoding="utf-8"))

        return {"output": proc.stdout[:1000], "issues": []}
    except Exception as exc:
        err = f"Arachni execution failed: {exc}"
        log.warning(f"[Scanner2: Arachni] {err}")
        return {"error": err, "issues": []}


def _run_nuclei(registry: Registry, run_dir: Path, max_minutes: int, log: logging.Logger) -> dict[str, Any]:
    """Jalankan Nuclei (baik container maupun binary host jika ada)."""
    log.info("[Scanner2: Nuclei] Memulai Nuclei scan...")
    target_url = registry.target_url
    raw_findings: list[dict[str, Any]] = []

    # Buat targets file
    targets_file = run_dir / "nuclei_targets.txt"
    urls = {target_url}
    for r in registry.routes:
        p = r.path
        for param in r.params:
            if param.location == "path":
                p = p.replace(f"{{{param.name}}}", "1")
        urls.add(urljoin(target_url.rstrip("/") + "/", p.lstrip("/")))
    targets_file.write_text("\n".join(urls), encoding="utf-8")

    docker_bin = shutil.which("docker")
    nuclei_bin = shutil.which("nuclei")

    # 1. Coba binary lokal jika tersedia
    if nuclei_bin:
        log.info(f"[Scanner2: Nuclei] Menggunakan local binary: {nuclei_bin}")
        out_jsonl = run_dir / "nuclei_out.jsonl"
        cmd = [
            nuclei_bin,
            "-list", str(targets_file),
            "-tags", "sqli,xss,cmdi,lfi",
            "-severity", "critical,high,medium,low,info",
            "-jsonl",
            "-output", str(out_jsonl),
            "-silent",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=max_minutes * 60)
            if out_jsonl.exists():
                for line in out_jsonl.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        try:
                            raw_findings.append(json.loads(line))
                        except Exception:
                            pass
            return {"findings": raw_findings}
        except Exception as exc:
            log.warning(f"[Scanner2: Nuclei] Local execution error: {exc}")

    # 2. Coba Docker compose exec jika container nuclei aktif
    if docker_bin:
        log.info("[Scanner2: Nuclei] Mencoba eksekusi lewat Docker container nuclei...")
        try:
            # Ganti localhost dengan nama service di network audit-net jika di docker
            docker_target = target_url.replace("localhost", "juice-shop").replace("127.0.0.1", "juice-shop")
            cmd = [
                docker_bin, "compose", "exec", "-T", "nuclei",
                "nuclei",
                "-u", docker_target,
                "-tags", "sqli,xss,cmdi,lfi",
                "-jsonl",
                "-silent",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_minutes * 60)
            for line in proc.stdout.splitlines():
                if line.strip():
                    try:
                        raw_findings.append(json.loads(line))
                    except Exception:
                        pass
            if raw_findings:
                return {"findings": raw_findings}
        except Exception as exc:
            log.warning(f"[Scanner2: Nuclei] Docker compose nuclei error: {exc}")

    # 3. Fallback bila tool belum terpasang
    err = "Nuclei tidak ditemukan di host dan Docker tidak aktif. Hasil dicatat kosong."
    log.warning(f"[Scanner2: Nuclei] {err}")
    return {"error": err, "findings": []}


def run_scanner2(
    registry: Registry,
    run_dir: str | Path,
    scanner: str = "nuclei",
    max_minutes: int = 30,
    log: logging.Logger | None = None,
) -> dict[str, Any]:
    """Jalankan scanner kedua (arachni atau nuclei)."""
    if log is None:
        log = logger

    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    out_file = run_path / "scanner2_raw.json"

    scanner_choice = scanner.lower()
    raw_result: dict[str, Any] = {}

    if scanner_choice == "arachni":
        raw_result = _run_arachni(registry, run_path, max_minutes, log)
        # Jika Arachni gagal karena docker/lainnya, beri opsi fallback ke nuclei
        if "error" in raw_result:
            log.info("[Scanner2] Arachni gagal, mencoba fallback ke Nuclei...")
            nuclei_res = _run_nuclei(registry, run_path, max_minutes, log)
            if "error" not in nuclei_res:
                raw_result = nuclei_res
    else:
        raw_result = _run_nuclei(registry, run_path, max_minutes, log)

    out_file.write_text(json.dumps(raw_result, indent=2), encoding="utf-8")
    return raw_result


# ---------------------------------------------------------------------------
# Orkestrator Paralel
# ---------------------------------------------------------------------------
def run_security(
    registry: Registry,
    run_dir: str | Path,
    scanner2: str = "nuclei",
    parallel: bool = True,
    max_minutes: int = 30,
    api_key: str = "changeme",
    zap_url: str = "http://localhost:8080",
) -> dict[str, Any]:
    """Menjalankan ZAP dan Scanner kedua secara paralel dan menormalisasi temuan."""
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    log_file = run_path / "security.log"
    log = setup_security_logger(log_file)

    log.info("==================================================")
    log.info(f"Memulai Security Driver untuk run di: {run_path}")
    log.info(f"Target: {registry.target_url} | Scanner2: {scanner2} | Max Minutes: {max_minutes}")
    log.info("==================================================")

    zap_raw: dict[str, Any] = {}
    scanner2_raw: dict[str, Any] = {}

    if parallel:
        log.info("Menjalankan ZAP dan Scanner kedua secara PARALEL...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_zap = executor.submit(
                run_zap, registry, run_path, api_key, zap_url, max_minutes, log
            )
            future_scanner2 = executor.submit(
                run_scanner2, registry, run_path, scanner2, max_minutes, log
            )

            try:
                zap_raw = future_zap.result()
            except Exception as exc:
                log.error(f"ZAP runner exception: {exc}")
                zap_raw = {"error": str(exc), "alerts": []}

            try:
                scanner2_raw = future_scanner2.result()
            except Exception as exc:
                log.error(f"Scanner2 runner exception: {exc}")
                scanner2_raw = {"error": str(exc)}
    else:
        log.info("Menjalankan ZAP dan Scanner kedua secara SEKUENSIAL...")
        try:
            zap_raw = run_zap(registry, run_path, api_key, zap_url, max_minutes, log)
        except Exception as exc:
            log.error(f"ZAP runner exception: {exc}")
            zap_raw = {"error": str(exc), "alerts": []}

        try:
            scanner2_raw = run_scanner2(registry, run_path, scanner2, max_minutes, log)
        except Exception as exc:
            log.error(f"Scanner2 runner exception: {exc}")
            scanner2_raw = {"error": str(exc)}

    # Normalisasi temuan
    log.info("Menormalisasi hasil pemindaian...")

    # ZAP findings
    findings_zap: list[Finding] = normalize_zap(zap_raw)
    findings_zap_file = run_path / "findings_zap.json"
    findings_zap_data = [f.model_dump(by_alias=True) for f in findings_zap]
    findings_zap_file.write_text(json.dumps(findings_zap_data, indent=2), encoding="utf-8")
    log.info(f"[ZAP] {len(findings_zap)} normalized findings disimpan ke {findings_zap_file.name}")

    # Scanner2 findings
    findings_s2: list[Finding] = []
    if "issues" in scanner2_raw:
        findings_s2 = normalize_arachni(scanner2_raw)
    else:
        findings_s2 = normalize_nuclei(scanner2_raw)

    findings_s2_file = run_path / "findings_scanner2.json"
    findings_s2_data = [f.model_dump(by_alias=True) for f in findings_s2]
    findings_s2_file.write_text(json.dumps(findings_s2_data, indent=2), encoding="utf-8")
    log.info(f"[Scanner2] {len(findings_s2)} normalized findings disimpan ke {findings_s2_file.name}")

    summary = {
        "target_url": registry.target_url,
        "zap_findings_count": len(findings_zap),
        "scanner2_findings_count": len(findings_s2),
        "zap_raw_file": str(run_path / "zap_raw.json"),
        "scanner2_raw_file": str(run_path / "scanner2_raw.json"),
        "findings_zap_file": str(findings_zap_file),
        "findings_scanner2_file": str(findings_s2_file),
        "zap_attack_requests_file": str(run_path / "zap_attack_requests.json"),
    }
    log.info(f"Security scan selesai. Summary: {summary}")
    return summary
