"""Active Defense Verifier (mitmproxy + ML-WAF).

Menjalankan mitmdump dengan reverse proxy add-on WAF, mengirim himpunan uji real-time
yang independen dari dataset pelatihan CSIC 2010 (normal traffic vs zap active scan attacks),
mengevaluasi akurasi pemblokiran, FPR, matriks konfusi, dan membandingkannya dengan baseline.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import numpy as np

from audit.mlwaf.features import is_attack_baseline
from audit.schemas import Registry

logger = logging.getLogger("audit.waf_verifier")


def _find_mitmdump() -> str | None:
    """Mencari binary mitmdump di virtualenv atau PATH sistem."""
    venv_bin = Path(sys.prefix) / "Scripts" / "mitmdump.exe"
    if venv_bin.exists():
        return str(venv_bin)
    venv_bin_nix = Path(sys.prefix) / "bin" / "mitmdump"
    if venv_bin_nix.exists():
        return str(venv_bin_nix)
    return shutil.which("mitmdump")


def build_realtime_test_set(
    registry: Registry,
    run_dir: Path,
    num_normal: int = 50,
) -> list[dict[str, Any]]:
    """Membangun himpunan uji real-time yang TERPISAH dari dataset latih CSIC 2010.

    Komposisi:
    - Normal (label=0): Permintaan sah yang digenerasi dari spesifikasi registry.
    - Berbahaya (label=1): Riwayat request active scan ZAP (zap_attack_requests.json)
      dan payload uji injeksi sintetis jika berkas ZAP kosong.
    """
    test_set: list[dict[str, Any]] = []

    # 1. Traffic Normal (Label = 0)
    for i in range(num_normal):
        route = registry.routes[i % len(registry.routes)]
        method = route.method.upper()
        path = route.path
        for p in route.params:
            if p.location == "path":
                path = path.replace(f"{{{p.name}}}", str((i % 10) + 1))

        query = ""
        if method == "GET":
            query = f"q=item_{i}&page=1" if "search" in path else f"ref=web_{i}"

        body = ""
        if method in ("POST", "PUT"):
            body = json.dumps({"email": f"user{i}@test.com", "password": "ValidPassword123!", "seq": i})

        test_set.append({
            "method": method,
            "path": path,
            "query": query,
            "body": body,
            "label": 0,
            "category": "normal_functional",
        })

    # 2. Traffic Serangan (Label = 1) dari ZAP Attack Requests
    zap_attacks_file = run_dir / "zap_attack_requests.json"
    zap_loaded = 0
    if zap_attacks_file.exists():
        try:
            raw_zap = json.loads(zap_attacks_file.read_text(encoding="utf-8"))
            for req in raw_zap[:100]:
                url_str = req.get("url", "/")
                # Ambil path dari url
                from urllib.parse import urlparse
                parsed = urlparse(url_str)
                test_set.append({
                    "method": req.get("method", "GET").upper(),
                    "path": parsed.path or "/",
                    "query": parsed.query or "",
                    "body": req.get("body", ""),
                    "label": 1,
                    "category": "zap_active_scan",
                })
                zap_loaded += 1
        except Exception as exc:
            logger.warning(f"Gagal membaca zap_attack_requests.json: {exc}")

    # Jika ZAP attack requests kosong (misal ZAP offline saat scan awal), lengkapi dengan payload serangan variatif
    if zap_loaded == 0:
        attack_payloads = [
            ("POST", "/rest/user/login", "", "email=admin%27+or+1%3D1--&password=foo"),
            ("GET", "/rest/products/search", "q=apple%27+union+select+1%2C2%2C3--", ""),
            ("GET", "/rest/products/search", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", ""),
            ("GET", "/rest/track-order/1", "id=1%27+or+%271%27%3D%271", ""),
            ("POST", "/api/Feedbacks", "", json.dumps({"comment": "<iframe src=javascript:alert(1)>", "rating": 5})),
            ("GET", "/ftp", "file=../../../../etc/passwd", ""),
            ("GET", "/api/Products/1", "id=1; cat /etc/shadow", ""),
            ("POST", "/api/Users", "", json.dumps({"email": "test' OR 'a'='a", "password": "pass"})),
            ("GET", "/rest/admin/application-version", "cmd=whoami; id", ""),
            ("GET", "/api/Challenges", "search=sleep(5)--", ""),
        ]
        # Lipat gandakan menjadi 50 request serangan
        for idx in range(num_normal):
            m, p, q, b = attack_payloads[idx % len(attack_payloads)]
            test_set.append({
                "method": m,
                "path": p,
                "query": q,
                "body": b,
                "label": 1,
                "category": "synthetic_injection_test",
            })

    return test_set


def _save_waf_cm_plot(cm: np.ndarray, out_path: Path) -> None:
    """Menyimpan matriks konfusi pengujian WAF ke gambar PNG."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.figure(figsize=(5.5, 4.5))
        plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Greens)
        plt.title("Real-Time ML-WAF Verification - Confusion Matrix", fontsize=11, pad=12)
        plt.colorbar()

        classes = ["Normal (0)", "Attack (1)"]
        tick_marks = np.arange(len(classes))
        plt.xticks(tick_marks, classes, fontsize=10)
        plt.yticks(tick_marks, classes, fontsize=10)

        thresh = cm.max() / 2.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                plt.text(
                    j, i, format(cm[i, j], "d"),
                    horizontalalignment="center",
                    color="white" if cm[i, j] > thresh else "black",
                    fontsize=12,
                    fontweight="bold",
                )

        plt.ylabel("True Class", fontsize=10)
        plt.xlabel("WAF Decision (Predicted)", fontsize=10)
        plt.tight_layout()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path, dpi=200)
        plt.close()
    except Exception as exc:
        logger.warning(f"Gagal menyimpan WAF CM plot: {exc}")


def run_waf_verifier(
    registry: Registry,
    run_dir: str | Path,
    proxy_port: int = 8082,
    model_path: str | Path = "audit/mlwaf/model.joblib",
    target_url: str | None = None,
) -> dict[str, Any]:
    """Menjalankan mitmdump reverse proxy WAF dan menguji akurasi pemblokiran real-time."""
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)
    target = target_url or registry.target_url
    log_file = run_path / "waf_decisions.jsonl"
    out_json = run_path / "waf.json"
    cm_png = run_path / "waf_confusion_matrix.png"

    mitmdump_bin = _find_mitmdump()
    if not mitmdump_bin:
        err = "mitmdump executable tidak ditemukan di virtualenv atau PATH."
        logger.error(f"[WAF Verifier] {err}")
        res_error = {"error": err, "status": "FAIL", "evaluated": False}
        out_json.write_text(json.dumps(res_error, indent=2), encoding="utf-8")
        return res_error

    addon_script = Path(__file__).resolve().parent.parent / "mlwaf" / "mitm_addon.py"

    env = os.environ.copy()
    env["MLWAF_MODEL_PATH"] = str(Path(model_path).resolve())
    env["WAF_LOG_FILE"] = str(log_file.resolve())
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent.parent)

    cmd = [
        mitmdump_bin,
        "--mode", f"reverse:{target}",
        "-p", str(proxy_port),
        "-s", str(addon_script),
        "--set", "flow_detail=0",
    ]

    logger.info(f"[WAF Verifier] Memulai mitmdump reverse proxy di port {proxy_port} -> {target}...")
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        # Tunggu proxy siap
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        ready = False
        for _ in range(20):  # Maksimal 10 detik
            try:
                r = httpx.get(f"{proxy_url}/", timeout=1.0)
                ready = True
                break
            except Exception:
                time.sleep(0.5)

        if not ready:
            logger.warning("[WAF Verifier] Proxy belum merespons, tetap melanjutkan pengujian...")

        # Bangun himpunan uji real-time
        test_set = build_realtime_test_set(registry, run_path, num_normal=40)
        logger.info(f"[WAF Verifier] Mengirim {len(test_set)} permintaan uji real-time lewat proxy...")

        y_true: list[int] = []
        y_pred: list[int] = []
        y_baseline: list[int] = []

        with httpx.Client(timeout=5.0) as client:
            for item in test_set:
                method = item["method"]
                url = f"{proxy_url}{item['path']}"
                if item["query"]:
                    url = f"{url}?{item['query']}"

                headers = {"Content-Type": "application/json"}
                blocked = False

                try:
                    resp = client.request(method, url, content=item["body"], headers=headers)
                    # Cek apakah diblokir WAF
                    if resp.status_code == 403 and resp.headers.get("X-WAF-Decision") == "blocked":
                        blocked = True
                except Exception:
                    # Timeout atau connection closed oleh proxy WAF
                    blocked = True

                pred_label = 1 if blocked else 0
                base_label = is_attack_baseline(method, item["path"], item["query"], item["body"])

                y_true.append(item["label"])
                y_pred.append(pred_label)
                y_baseline.append(base_label)

        # Evaluasi Metrik Real-Time
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

        total = len(y_true)
        acc = float((tp + tn) / total) if total > 0 else 0.0
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        # Baseline metrics
        b_tp = sum(1 for yt, yb in zip(y_true, y_baseline) if yt == 1 and yb == 1)
        b_tn = sum(1 for yt, yb in zip(y_true, y_baseline) if yt == 0 and yb == 0)
        b_fp = sum(1 for yt, yb in zip(y_true, y_baseline) if yt == 0 and yb == 1)
        b_fn = sum(1 for yt, yb in zip(y_true, y_baseline) if yt == 1 and yb == 0)
        b_acc = float((b_tp + b_tn) / total) if total > 0 else 0.0

        # Ambil akurasi hold-out dari mlwaf_report.json jika tersedia
        hold_out_acc = None
        mlwaf_rep_file = Path("results/mlwaf_report.json")
        if mlwaf_rep_file.exists():
            try:
                rep_data = json.loads(mlwaf_rep_file.read_text(encoding="utf-8"))
                hold_out_acc = rep_data.get("decision_tree", {}).get("accuracy")
            except Exception:
                pass

        target_passed = acc >= 0.90

        cm_arr = np.array([[tn, fp], [fn, tp]])
        _save_waf_cm_plot(cm_arr, cm_png)

        waf_result = {
            "timestamp": time.time(),
            "proxy_port": proxy_port,
            "target_url": target,
            "total_test_requests": total,
            "normal_requests_count": sum(1 for yt in y_true if yt == 0),
            "attack_requests_count": sum(1 for yt in y_true if yt == 1),
            "realtime_metrics": {
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "fpr": round(fpr, 4),
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            },
            "baseline_accuracy": round(b_acc, 4),
            "hold_out_accuracy_csic": hold_out_acc,
            "target_accuracy_threshold": ">= 90%",
            "target_passed": target_passed,
            "note": "Verifikasi ini independen; hasil WAF tidak masuk ke rumus UPRI (Ssec murni dari Union List DAST), namun ditampilkan di laporan kesiapan produksi.",
        }

        out_json.write_text(json.dumps(waf_result, indent=2), encoding="utf-8")
        logger.info(f"[WAF Verifier] Selesai: Akurasi={acc*100:.2f}%, FPR={fpr*100:.2f}% | Hasil di {out_json}")
        return waf_result

    except Exception as exc:
        err = f"WAF verifier execution failed: {exc}"
        logger.error(f"[WAF Verifier] {err}")
        res_error = {"error": err, "evaluated": False}
        out_json.write_text(json.dumps(res_error, indent=2), encoding="utf-8")
        return res_error

    finally:
        if proc is not None:
            logger.info("[WAF Verifier] Menghentikan mitmdump subprocess...")
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except Exception:
                proc.kill()
