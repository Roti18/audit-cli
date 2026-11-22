# audit-cli

**Framework Audit Kesiapan Produksi API berbasis CLI** – Proyek Skripsi

Framework otomasi pengujian kesiapan produksi (*production readiness*) antarmuka pemrograman aplikasi (API) yang mengintegrasikan pengujian fungsional kontrak OpenAPI, pemindaian keamanan multi-alat dinamis (DAST ZAP + Nuclei/Arachni), verifikasi pertahanan aktif *Machine Learning Web Application Firewall* (ML-WAF berbasis Decision Tree CRISP-DM pada mitmproxy), pengujian beban bertahap (k6), serta mesin kalkulasi *Unified Production Readiness Index* (UPRI) dengan mekanisme *kill switch* protektif.

---

## Quick Start

```powershell
# 1. Pastikan Python virtual environment aktif
.\.venv\Scripts\Activate.ps1

# 2. Jalankan service target lab (Docker Desktop)
docker compose up -d

# 3. Verifikasi layanan
docker compose ps
curl http://localhost:3000/                           # OWASP Juice Shop
curl http://localhost:5000/api/v1/products           # Clean Production API (Jalur Sukses)
curl http://localhost:8080/JSON/core/view/version/    # OWASP ZAP API

# 4. Jalankan Full Audit End-to-End Jalur Sukses (Target: Clean API)
audit http://localhost:5000 --spec data/openapi_clean_api.yaml --run-id clean_api --quick --scale 0.1

# 5. Jalankan Full Audit End-to-End Target Rentan (Target: OWASP Juice Shop)
audit http://localhost:3000 --spec data/openapi_juiceshop.yaml --run-id juiceshop --quick --scale 0.1

# 6. Buka Laporan Interaktif HTML (Mandiri, Tanpa CDN)
start results/clean_api/report.html
start results/juiceshop/report.html

# 7. Jalankan Seluruh Unit Test (121 test passed)
pytest -v
```

---

## Struktur Repositori

```
audit-cli/
  docker-compose.yml              # Definisi target (juice-shop, clean-api, zap, nuclei)
  pyproject.toml                  # Metadata proyek & entry point CLI 'audit'
  README.md                       # Dokumentasi lengkap & keputusan desain
  TODO_MANUAL.md                  # Checklist operasional mahasiswa
  data/
    csic/                         # Dataset HTTP CSIC 2010 (anomali & normal)
    openapi_juiceshop.yaml        # Kontrak OpenAPI 3.0 OWASP Juice Shop (15 rute)
    openapi_clean_api.yaml        # Kontrak OpenAPI 3.0 Clean Mock API (7 rute)
    ground_truth_juiceshop.json   # 15 kerentanan acuan OWASP Juice Shop
    ground_truth_clean_api.json   # Acuan nihil kerentanan (jalur PASSED)
  results/
    clean_api/                    # Output audit sukses: report.html, report.json, report.csv, metrics.csv
    juiceshop/                    # Output audit rentan (REJECTED by Kill Switch)
    bab4/                         # Paket bukti kuantitatif Bab IV (Tabel MD/CSV + Grafik PNG)
  audit/
    __init__.py
    cli.py                        # Dispatcher CLI utama & subcommands Typer
    schemas.py                    # Skema Pydantic (Route, Registry, Finding, Scorecard, dll.)
    clean_api.py                  # Layanan mock API produksi bersih (Flask)
    discovery/
      openapi.py                  # Parser OpenAPI 3.0 & Swagger 2.0 dengan resolusi $ref
    drivers/
      functional.py               # Pengujian kontrak skema & validasi tipe data (TC-F01..F04)
      security.py                 # Orkestrasi paralel DAST ZAP + scanner kedua
      waf_verifier.py             # Add-on verifikasi mitigasi ML-WAF mitmproxy
      performance.py              # Generator pengujian k6 & monitor resource kontainer
    security/
      normalizer.py               # Normalisasi route ({id}), method, & pemetaan CWE
      union.py                    # Agregator Union List multitool deterministik
      metrics.py                  # Kalkulasi metrik DAST (Precision, Recall, F1)
    mlwaf/
      features.py                 # Ekstraksi 26 fitur rekayasa HTTP (zero train-serve skew)
      train.py                    # Pipeline CRISP-DM, GridSearchCV, & Decision Tree
      mitm_addon.py               # Add-on mitmproxy reverse proxy pencegat serangan (port 8082)
      model.joblib                # Model terkompilasi scikit-learn
    scorecard/
      engine.py                   # Engine murni kalkulasi Ssec, Pperf, UPRI, & Kill Switch
    report/
      generator.py                # Generator ekspor multi-format (JSON, CSV, HTML)
      templates/
        report.html.j2            # Template HTML mandiri, responsif, dan siap cetak (zero CDN)
  scripts/
    make_chapter4_tables.py       # Pembuat tabel kuantitatif RQ1-RQ5 & grafik komparasi
    run_audit_clean_api.py        # Runner otomasi skenario PASSED
    prepare_juiceshop_run.py      # Runner otomasi skenario REJECTED
  tests/
    test_schemas.py
    test_discovery.py
    test_functional.py
    test_normalizer.py
    test_security_driver.py
    test_mlwaf.py
    test_union_metrics.py
    test_scorecard.py
    test_performance.py
    test_waf_verifier.py
    test_report.py
    test_cli_pipeline.py
```

---

## Layanan Docker Staging

| Layanan | Image | Port | Karakteristik / Alokasi | Verifikasi Kesehatan |
|---|---|---|---|---|
| `juice-shop` | `bkimminich/juice-shop` | 3000 | Target rentan acuan (Node.js/Express), 2 CPU / 2 GB RAM | `curl -s http://localhost:3000/` |
| `clean-api` | `python:3.11-slim` (Flask) | 5000 | Target aman acuan (Validasi ketat, 400/401 handling), 2 CPU / 2 GB RAM | `curl -s http://localhost:5000/api/v1/products` |
| `zap` | `zaproxy/zap-stable` | 8080 | Pemindai DAST primer via API daemon | `curl http://localhost:8080/JSON/core/view/version/` |
| `nuclei` | `projectdiscovery/nuclei:latest` | – | Pemindai DAST sekunder berbasis templat YAML | `docker compose exec nuclei nuclei --version` |

---

## Versi Alat & Spesifikasi Lingkungan Pengujian

Tabel berikut memuat versi rilis aktual dari setiap perangkat lunak yang terpasang pada host uji coba Windows 11:

| Komponen Perangkat Lunak | Versi Aktual | Keterangan / Konfigurasi |
|---|---|---|
| **Sistem Operasi Host** | Windows 11 Pro (10.0.26200) | Host pengujian & orchestrator CLI |
| **Python Runtime** | Python 3.14.7 (.venv) / 3.12.4 | Eksekusi seluruh modul audit & ML |
| **k6 Load Generator** | v1.5.0 (go1.25.5, windows/amd64) | Terpasang langsung pada host PATH |
| **mitmproxy / mitmdump** | 12.3.1 (Python 3.14.7, OpenSSL 4.0.3) | Add-on ML-WAF reverse proxy (port 8082) |
| **OWASP ZAP** | zaproxy/zap-stable (Docker 2.14+) | Daemon mode port 8080 |
| **ProjectDiscovery Nuclei** | projectdiscovery/nuclei:latest | Eksekusi berbasis kontainer Docker |
| **Scikit-Learn** | >= 1.3 (DecisionTreeClassifier) | Kriteria entropy, max_depth=8, 5-fold CV |
| **Typer & Rich** | >= 0.9 / >= 13.0 | CLI interface & tabel visual terminal |

---

## Panduan Perintah CLI (`audit`)

Framework menyediakan antarmuka CLI terpadu via perintah utama `audit <target-url>` serta sub-perintah granular:

### 1. Perintah Terpadu End-to-End (`audit <url>`)
```powershell
audit <target-url> [OPTIONS]

Opsi:
  --spec PATH               Jalur ke berkas spesifikasi OpenAPI 3.0 / Swagger 2.0 (YAML/JSON).
  --header "K: V"           Header HTTP tambahan (misal: "Authorization: Bearer token").
  --run-id TEXT             Nama direktori output run (default: timestamp ISO).
  --scanner2 TEXT           Pemindai DAST sekunder: 'nuclei' atau 'arachni' (default: nuclei).
  --quick / --no-quick      Durasi k6 singkat (20s/profil) untuk pengujian cepat (default: quick).
  --scale FLOAT             Faktor pengali VU beban k6 (default: 0.1 untuk laptop, 1.0 untuk lab).
  --reuse-run               Gunakan data artefak DAST/WAF/Perf yang sudah ada pada --run-id.
  --skip-functional         Lewati pengujian fungsional kontrak skema.
  --skip-security           Lewati pemindaian DAST (ZAP + Nuclei).
  --skip-waf                Lewati pengujian reverse proxy ML-WAF.
  --skip-perf               Lewati pengujian beban performa k6.
  --verbose                 Tampilkan rincian debug lengkap di konsol.
```

### 2. Sub-Perintah Granular
```powershell
# Discovery & Endpoint Registry
audit discover <url> --spec data/openapi_juiceshop.yaml --out results/run1

# Pengujian Fungsional Kontrak Skema
audit functional --registry results/run1/registry.json --run-id run1

# Pemindaian Keamanan DAST (ZAP + Nuclei)
audit security --registry results/run1/registry.json --scanner2 nuclei --out results/run1 --max-minutes 30

# Pelatihan Model ML-WAF (CRISP-DM)
audit train-waf --data data/csic --out audit/mlwaf/model.joblib

# Evaluasi Metrik Recall DAST vs Ground Truth
audit security-report --run-dir results/run1 --ground-truth data/ground_truth_juiceshop.json

# Verifikasi Active Defense (mitmproxy ML-WAF)
audit waf --registry results/run1/registry.json --out results/run1 --proxy-port 8082

# Pengujian Beban & Resource Monitoring (k6)
audit perf --registry results/run1/registry.json --out results/run1 --quick --scale 0.1

# Kalkulasi Scorecard UPRI & Evaluasi Kill Switch
audit score --run-dir results/run1 --perf-file results/run1/performance.json

# Generate Laporan Multi-Format (HTML, JSON, CSV)
audit report --run-dir results/clean_api
```

---

## Kode Keluar (*Exit Codes*) CLI

Mendukung integrasi otomatis pada pipeline CI/CD dengan kode status deterministik:

| Kode Status | Label Status | Makna Operasional |
|:---:|---|---|
| `0` | **PASSED** | $\text{UPRI} \ge 85.0$ dan tidak ada *kill switch* aktif. Siap rilis ke produksi. |
| `1` | **CONDITIONAL PASS** | $70.0 \le \text{UPRI} < 85.0$ dan tidak ada *kill switch*. Perlu perbaikan non-kritis. |
| `2` | **REJECTED** | $\text{UPRI} < 70.0$ ATAU terdapat *kill switch* aktif (Critical/High vuln atau error/latensi tinggi). Rilis dibatalkan. |
| `3` | **INCOMPLETE** | Komponen penilaian wajib dilewati atau gagal dievaluasi. |
| `4` | **FATAL ERROR** | Target tidak dapat dijangkau atau Endpoint Registry kosong saat tahap discovery. |

---

## Format & Berkas Output (`results/<run_id>/`)

Setiap eksekusi audit menghasilkan artefak terstruktur pada direktori `results/<run_id>/`:
- `report.html`: Laporan interaktif mandiri (*single-page standalone*, CSS inline, **zero external CDN**), memuat banner keputusan, rincian skor UPRI, daftar pemicu *kill switch*, tabel temuan *Union List*, tabel perbandingan recall DAST, evaluasi ML-WAF (grafik matriks konfusi tersemat base64), visualisasi progress bar performa SVG/CSS, serta metadata lingkungan mesin penguji.
- `report.json`: Agregasi lengkap seluruh data audit mesin dalam satu objek JSON terstruktur.
- `report.csv`: Tabel temuan kerentanan *Union List* terdeduplikasi (`tool`, `cwe`, `severity`, `route`, `param`).
- `metrics.csv`: Tabel metrik performa tiap profil beban (`profile`, `vus`, `rps`, `avg_latency_ms`, `p95_ms`, `error_rate`, `pperf`).
- `registry.json`: Katalog endpoint yang berhasil diparsing dari spesifikasi OpenAPI.
- `functional.json`: Hasil pengujian skema fungsional dan *pass rate*.
- `union.json`: Daftar temuan gabungan DAST beserta irisan antar pemindai.
- `security_metrics.json`: Perhitungan TP, FP, FN, Precision, Recall, dan $F_1$-measure terhadap *ground truth*.
- `waf.json`: Metrik akurasi deteksi real-time ML-WAF dan *False Positive Rate* (FPR).
- `performance.json`: Rincian latensi persentil, throughput RPS, dan konsumsi CPU/memori kontainer target.

---

## Formula Scorecard & Ambang Keputusan

$$\text{UPRI} = 0.6 \times S_{\text{sec}} + 0.4 \times P_{\text{perf}}$$

### 1. Skor Keamanan ($S_{\text{sec}}$)
$$S_{\text{sec}} = \max\left(0, 100 - \sum (N_i \times W_i)\right)$$
*Bobot Penalti ($W_i$): Critical = 100, High = 50, Medium = 15, Low = 5.*

### 2. Skor Performa Gabungan ($P_{\text{perf}}$)
Dihitung rata-rata dari profil *Typical*, *Peak*, dan *Stress*:
$$P_{\text{perf}} = 0.5 \times (100 \times (1 - \text{ER})) + 0.3 \times P_{\text{latency}} + 0.2 \times P_{\text{resource}}$$
- $P_{\text{latency}} = \left(\frac{L - \mu}{L}\right) \times 100 \quad \text{jika } \mu < L \text{ (ambang } L = 500\text{ ms)}, \text{else } 0$
- $P_{\text{resource}} = 100 - \max(\text{cpu\_pct}, \text{mem\_pct}) \quad \text{diclam 0..100}$

### 3. Mekanisme Protektif *Kill Switch*
Keputusan otomatis dipaksa menjadi **REJECTED (Exit Code 2)** jika salah satu kondisi berikut terpenuhi:
1. Terdapat $\ge 1$ kerentanan berkategori **Critical** atau **High** pada Union List.
2. Tingkat kesalahan $\text{ER} > 0\%$ pada profil beban *Typical* atau *Peak*.
3. Latensi rata-rata $\mu \ge 500\text{ ms}$ ($P_{\text{latency}} = 0$) pada profil beban *Typical* atau *Peak*.

---

## Keputusan Desain (*Design Decisions*)

1. **Pperf dihitung per profil** (typical, peak, stress), lalu $P_{\text{perf}}$ final = rata-rata ketiganya. Profil Spike dicatat terpisah karena bersifat transien dan bertujuan menguji resiliensi lonjakan mendadak.
2. **Presource dinormalisasi terhadap kuota kontainer** (2 CPU, 2 GB RAM). Nilai puncak (*peak*) selama pengujian digunakan untuk mengukur batas aman *headroom*.
3. **Nuclei sebagai scanner kedua default** menggantikan Arachni yang telah usang (*deprecated*). Nuclei memiliki ribuan templat aktif dan integrasi Docker yang stabil.
4. **Eksekusi Paralel DAST** – Pemindaian ZAP dan Scanner kedua berjalan secara simultan menggunakan `ThreadPoolExecutor`, memangkas durasi audit hingga 50%.
5. **Fault Tolerance Scanner** – Kegagalan salah satu pemindai tidak menghentikan audit; error dicatat dan pemindai yang berhasil tetap diolah ke Union List.
6. **Normalisasi Route & Deduplikasi Cerdas** – Segmen path numerik (`/products/42`) atau UUID dinormalisasi menjadi `{id}` untuk memastikan deduplikasi temuan lintas-alat tepat sasaran.
7. **Penyusunan Dataset WAF Real-Time** – Riwayat permintaan serangan Active Scan ZAP diekstrak otomatis sebagai himpunan uji serangan WAF tanpa menggunakan sampel CSIC berulang.
8. **Spesifikasi OpenAPI Representatif** – 15 rute inti Juice Shop dipetakan di `data/openapi_juiceshop.yaml` dan 7 rute produksi di `data/openapi_clean_api.yaml`.
9. **Resiliensi Driver Fungsional** – Ketidaksesuaian skema dicatat sebagai test case gagal (`passed: false`), tanpa memicu *crash* eksepsi Python.
10. **Proteksi Lingkungan Lokal** – URL non-lokal diblokir kecuali disertakan flag eksplisit `--allow-remote`, mencegah pemindaian tidak sengaja ke domain publik.
11. **Serialisasi Alias Skema** – Field parameter OpenAPI menggunakan alias internal `"in"` untuk mematuhi standar JSON Schema.
12. **Modul Ekstraksi Fitur Tunggal (Zero Train-Serve Skew)** – Berkas `audit/mlwaf/features.py` dipakai secara identik oleh tahap training dan runtime mitmproxy addon.
13. **Metodologi CRISP-DM pada ML-WAF** – Pelatihan model mengikuti 6 tahap standar industri: Business Understanding hingga Deployment terpaket.
14. **Deduplikasi Sebelum Pembagian Sampel** – Menghilangkan duplikat permintaan HTTP sebelum *stratified split* 80:20 guna mencegah *data leakage*.
15. **Fallback Generator Dataset Sintetis** – Jika file CSIC 2010 belum diunduh, sistem membuat sampel uji sintetis agar pengujian pipeline tetap lulus.
16. **Union List Aggregator Deterministik** – Himpunan gabungan temuan didedup berdasarkan kunci `(cwe, route, param, method)` dengan prioritas severity tertinggi dan urutan stabil.
17. **Toleransi Pencocokan Ground Truth** – Pencocokan temuan ke *ground truth* berbasis kesamaan CWE dan route ternormalisasi; kesamaan nama parameter dijadikan parameter toleransi opsional.
18. **Scorecard Engine Deterministik (Fungsi Murni)** – Komputasi skor murni tanpa operasi I/O jaringan untuk memastikan reproduktibilitas hasil 100%.
19. **Kill Switch Protektif** – Menolak rilis sistem secara mutlak jika ada kerentanan kritis atau degradasi performa pada trafik normal, meskipun nilai total UPRI secara matematis tampak tinggi.
20. **Active Defense Verifier (mitmproxy ML-WAF)** – Add-on reverse proxy berjalan di port 8082, memblokir serangan dengan respons HTTP 403 Forbidden dan header `X-WAF-Decision: blocked`.
21. **Performance Driver (k6) & Resource Monitoring** – Skrip k6 dinamis dengan sampling metrik kontainer via `docker stats` dan fallback mulus ke `psutil`. Target kontainer di-reset sebelum pengujian profil baru.
22. **Laporan Mandiri Tanpa Ketergantungan Eksternal (Zero CDN HTML)** – `report.html` menggunakan CSS murni tersemat inline dan grafik matriks konfusi dikonversi ke format base64 data URI. Laporan dapat dibuka secara offline, disimpan sebagai PDF, dan dicetak tanpa mengalami kerusakan tampilan.
23. **Benchmarking Netral dengan Layanan Clean API** – Untuk membuktikan secara empiris bahwa framework tidak menghasilkan keputusan bias (selalu menolak), disediakan layanan `clean-api` yang mematuhi praktik sanitasi input ketat sehingga secara sah membuktikan jalur kelulusan **PASSED (Exit Code 0, UPRI > 85)**.

---

## Batasan Penelitian (*Limitations*)

Sebagai bagian dari kejujuran akademik skripsi, batasan metodologis berikut diakui secara eksplisit:
1. **Durasi Beban Cepat vs Uji Ketahanan Panjang (*Quick vs Soak Testing*)**: Pengujian performa k6 pada opsi `--quick` (20 detik per profil) dirancang untuk verifikasi fungsional cepat pada laptop pengembang. Untuk pengujian kapasitas rilis produksi sesungguhnya, durasi pengujian beban disarankan berjalan minimal 10–30 menit per profil untuk mendeteksi potensi *memory leak* jangka panjang.
2. **Berbagi Sumber Daya Host Lokal (*Localhost Resource Sharing*)**: Eksekusi kontainer target, alat pemindai DAST, reverse proxy ML-WAF, dan generator k6 dilakukan pada satu mesin fisik yang sama (Windows 11). Lonjakan CPU oleh k6 atau pemindai DAST dapat memengaruhi latensi target secara minor dibandingkan arsitektur terdistribusi *dedicated testing server*.
3. **Penyusunan Ground Truth Berbasis Sampling Representatif**: Berkas *ground truth* Juice Shop mencakup 15 kerentanan representatif OWASP Top 10 API Security (SQLi, XSS, NoSQLi, BOLA) yang relevan dengan cakupan endpoint yang dipetakan, bukan seluruh tantangan (*challenges*) yang ada pada aplikasi target.

---

## Verifikasi Pengujian Unit

Seluruh modul telah divalidasi menggunakan rangkaian unit test komprehensif:

```powershell
.\.venv\Scripts\pytest -v
# Output: 121 passed in 39.79s (100% lulus)
```
