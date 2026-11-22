"""Mitmproxy Add-on: Reverse Proxy WAF berbasis ML (Decision Tree).

Memuat audit/mlwaf/model.joblib saat inisialisasi, mengekstrak fitur menggunakan
audit.mlwaf.features.extract_features yang SAMA persis dengan saat training (zero train-serve skew),
dan mencegat (intersep) permintaan HTTP:
- Jika terdeteksi berbahaya (label=1): Balas HTTP 403 Forbidden dengan header X-WAF-Decision: blocked.
- Jika terdeteksi normal (label=0): Teruskan ke server target dengan header X-WAF-Decision: allowed.
- Mencatat setiap keputusan ke results/<run_id>/waf_decisions.jsonl.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import joblib

# Pastikan audit package dapat diimpor saat dijalankan oleh mitmdump
current_dir = Path(__file__).resolve().parent
project_root = current_dir.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from mitmproxy import ctx, http
from audit.mlwaf.features import extract_features, normalize

logger = logging.getLogger("mlwaf.mitm")


def _log_info(msg: str) -> None:
    if hasattr(ctx, "log") and hasattr(ctx.log, "info"):
        ctx.log.info(msg)
    else:
        logger.info(msg)


def _log_warn(msg: str) -> None:
    if hasattr(ctx, "log") and hasattr(ctx.log, "warn"):
        ctx.log.warn(msg)
    else:
        logger.warning(msg)


def _log_error(msg: str) -> None:
    if hasattr(ctx, "log") and hasattr(ctx.log, "error"):
        ctx.log.error(msg)
    else:
        logger.error(msg)


class MLWAFAddon:
    def __init__(self) -> None:
        self.model = None
        self.model_path = Path(os.environ.get("MLWAF_MODEL_PATH", "audit/mlwaf/model.joblib"))
        self.log_file = Path(os.environ.get("WAF_LOG_FILE", "results/default/waf_decisions.jsonl"))
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.blocked_count = 0
        self.allowed_count = 0

    def load(self, loader) -> None:
        """Dipanggil saat mitmproxy mulai berjalan."""
        if self.model_path.exists():
            try:
                bundle = joblib.load(self.model_path)
                if isinstance(bundle, dict) and "model" in bundle:
                    self.model = bundle["model"]
                else:
                    self.model = bundle
                _log_info(f"[ML-WAF] Berhasil memuat model dari {self.model_path}")
            except Exception as exc:
                _log_error(f"[ML-WAF] Gagal memuat model: {exc}")
        else:
            _log_warn(f"[ML-WAF] Berkas model tidak ditemukan di {self.model_path}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Intersep setiap HTTP request sebelum dikirim ke target."""
        if self.model is None:
            flow.request.headers["X-WAF-Decision"] = "passthrough_no_model"
            return

        method = flow.request.method.upper()
        raw_url = flow.request.url
        from urllib.parse import urlparse
        parsed = urlparse(raw_url)
        path = parsed.path or flow.request.path or "/"
        query = parsed.query or ""

        try:
            body = flow.request.get_text() or ""
        except Exception:
            body = ""

        # Ekstraksi fitur identik dengan saat training
        features = extract_features(method=method, url=path, query=query, body=body)

        prediction = 0
        try:
            pred = self.model.predict([features])
            prediction = int(pred[0])
        except Exception as exc:
            _log_error(f"[ML-WAF] Error inferensi: {exc}")
            prediction = 0

        # Log keputusan
        decision_record = {
            "timestamp": time.time(),
            "method": method,
            "url": raw_url,
            "path": path,
            "prediction": "blocked" if prediction == 1 else "allowed",
            "label": prediction,
            "features_summary": {
                "non_alnum_ratio": features[49] if len(features) > 49 else 0.0,
                "is_post": features[50] if len(features) > 50 else 0.0,
            },
        }
        self._write_log(decision_record)

        if prediction == 1:
            # Blokir request (HTTP 403)
            self.blocked_count += 1
            _log_warn(f"[ML-WAF BLOCKED] {method} {path}")
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "error": "Forbidden",
                    "code": 403,
                    "message": "Permintaan diblokir oleh ML-WAF (Anomali/Serangan terdeteksi).",
                }).encode("utf-8"),
                {
                    "Content-Type": "application/json",
                    "X-WAF-Decision": "blocked",
                    "X-WAF-Rule": "DecisionTree-Entropy",
                },
            )
        else:
            # Loloskan request (HTTP Allow)
            self.allowed_count += 1
            flow.request.headers["X-WAF-Decision"] = "allowed"

    def response(self, flow: http.HTTPFlow) -> None:
        """Tambahkan header keputusan ke respons yang dikembalikan ke client."""
        waf_header = flow.request.headers.get("X-WAF-Decision", "allowed")
        if flow.response and "X-WAF-Decision" not in flow.response.headers:
            flow.response.headers["X-WAF-Decision"] = waf_header

    def _write_log(self, record: dict[str, Any]) -> None:
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass


addons = [MLWAFAddon()]
