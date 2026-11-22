# audit-cli

**Framework Audit Kesiapan Produksi API berbasis CLI** – Proyek Skripsi

## Quick Start

```bash
# 1. Install dependencies
pip install -e ".[dev]"

# 2. Start Docker services
docker compose up -d

# 3. Verify services
docker compose ps
curl http://localhost:3000/      # Juice Shop
curl http://localhost:8080/       # ZAP API

# 4. Run discovery
audit discover http://localhost:3000 --spec data/openapi_juiceshop.yaml --out results/run1

# 5. Run functional tests
audit functional --registry results/run1/registry.json --run-id run1

# 6. Run pytest
pytest
```

## Struktur Repo

```
audit-cli/
  docker-compose.yml
  pyproject.toml
  README.md
  data/                            # Spec & data manual
    openapi_juiceshop.yaml
  results/                         # Semua output run
  audit/
    __init__.py
    cli.py                         # Entry point Typer
    schemas.py                     # Pydantic models (Route, Registry, Finding, dll)
    discovery/openapi.py           # OpenAPI/Swagger parser
    drivers/functional.py          # Functional test driver
    drivers/security.py            # (Blok 2) ZAP + scanner kedua
    drivers/waf_verifier.py        # (Blok 2) ML-WAF check
    drivers/performance.py         # (Blok 2) k6 driver
    security/normalizer.py         # (Blok 2)
    security/union.py              # (Blok 2)
    security/metrics.py            # (Blok 2)
    scorecard/engine.py            # (Blok 2)
    report/generator.py            # (Blok 2)
    report/templates/report.html.j2
    mlwaf/features.py              # (Blok 3)
    mlwaf/train.py                 # (Blok 3)
    mlwaf/mitm_addon.py            # (Blok 3)
    mlwaf/model.joblib             # (Blok 3)
  tests/
    test_schemas.py
    test_discovery.py
    test_functional.py
    test_normalizer.py
    test_security_driver.py
    test_mlwaf.py
    test_union_metrics.py
    test_scorecard.py
```

## Docker Services

| Service    | Image                           | Port | Verifikasi                                            |
| ---------- | ------------------------------- | ---- | ----------------------------------------------------- |
| juice-shop | bkimminich/juice-shop           | 3000 | `curl -s http://localhost:3000/ \| head -5`           |
| zap        | zaproxy/zap-stable              | 8080 | `curl http://localhost:8080/JSON/core/view/version/`  |
| nuclei     | projectdiscovery/nuclei:latest  | –    | `docker compose exec nuclei nuclei --version`         |

### Tentang Scanner Kedua

Arachni sudah deprecated dan image Docker-nya tidak lagi maintained. Sebagai pengganti,
digunakan **Nuclei** (ProjectDiscovery) yang aktif dikembangkan dan memiliki template
vulnerability scanner yang luas.

Jika ingin tetap mencoba Arachni:
```bash
# Ganti service nuclei di docker-compose.yml dengan:
#   arachni:
#     image: arachni/arachni
#     ...
# Lalu jalankan:
docker compose run --rm arachni arachni --version
```

Pemilihan scanner kedua dikontrol lewat flag `--scanner2 nuclei|arachni` pada command `audit run`.

## CLI Commands

```bash
# Discovery saja
audit discover <url> [--spec PATH] [--header "Authorization: Bearer x"] --out results/<run_id>

# Functional test saja
audit functional --registry results/<run_id>/registry.json [--run-id <id>]

# Security audit saja (ZAP + scanner kedua)
audit security --registry results/<run_id>/registry.json --scanner2 nuclei --out results/<run_id> --max-minutes 30

# Pelatihan model ML-WAF (CRISP-DM)
audit train-waf [--data data/csic] [--out audit/mlwaf/model.joblib]

# Evaluasi Metrik Keamanan (ZAP vs Scanner2 vs Union vs Ground Truth)
audit security-report --run-dir results/<run_id> [--ground-truth data/ground_truth_juiceshop.json]

# Hitung Scorecard & Keputusan Kesiapan Produksi (UPRI + Kill Switch)
audit score --run-dir results/<run_id> [--perf-file results/<run_id>/performance.json]

# Verifikasi Real-Time Active Defense (ML-WAF mitmproxy reverse proxy)
audit waf --registry results/<run_id>/registry.json --out results/<run_id> [--proxy-port 8082]

# Pengujian Beban & Performa API (k6)
audit perf --registry results/<run_id>/registry.json --out results/<run_id> [--quick] [--scale 0.1]

# Full pipeline (Blok 2+)
audit run <url> [--spec PATH] [--header "..."] [--run-id <id>] [--scanner2 nuclei|arachni]
```

### Menjalankan Security Scan di Background & Monitoring

Pemindaian keamanan (ZAP + Scanner kedua) membutuhkan waktu 20–60 menit. Jalankan di background agar terminal tidak terblokir:

**Di Windows (PowerShell):**
```powershell
# Jalankan di background
Start-Process -NoNewWindow audit -ArgumentList "security --registry results/run1/registry.json --scanner2 nuclei --out results/run1 --max-minutes 30"

# Monitor progres secara real-time
Get-Content -Wait -Tail 20 results\run1\security.log
```

**Di Linux / macOS (Bash):**
```bash
# Jalankan di background
nohup audit security --registry results/run1/registry.json --scanner2 nuclei --out results/run1 --max-minutes 30 > /dev/null 2>&1 &

# Monitor progres secara real-time
tail -f results/run1/security.log
```

## Keputusan Desain

1. **Pperf dihitung per profil** (typical, peak, stress, spike), lalu Pperf final = rata-rata
   typical+peak+stress. Spike dilaporkan terpisah karena sifatnya yang sementara/transient dan
   tidak merepresentasikan kondisi operasi normal.

2. **Presource = 100 − max(cpu_pct, mem_pct)** dengan cpu_pct dinormalisasi terhadap batas
   2 core dan mem_pct terhadap 2 GB. Nilai puncak (peak) selama tes yang digunakan, dibatasi
   0–100. Ini menyederhanakan metrik resource menjadi satu angka "headroom".

3. **Nuclei sebagai scanner kedua** (pengganti Arachni yang deprecated). Nuclei aktif
   dikembangkan, memiliki >6000 template vulnerability, dan lebih reliable di Docker. Jika `--scanner2 arachni` dipilih tetapi gagal/tidak ada docker, sistem secara otomatis mencoba fallback ke Nuclei.

4. **Eksekusi Paralel ZAP & Scanner kedua** – Driver keamanan menggunakan `ThreadPoolExecutor` untuk menjalankan pemindaian ZAP dan Scanner kedua secara bersamaan, menghemat waktu total eksekusi hingga ~50%.

5. **Fault Tolerance Scanner** – Jika salah satu scanner (ZAP atau Scanner kedua) gagal, error dicatat dalam file raw masing-masing (`zap_raw.json` atau `scanner2_raw.json`), dan proses normalisasi tetap berjalan tanpa membuat seluruh proses audit crash.

6. **Normalisasi Route & Deduplikasi** – Segmen path berupa numerik (misal `/api/Products/42`) atau format UUID secara otomatis diganti menjadi `{id}` (`/api/Products/{id}`), dan query string dihilangkan agar deduplikasi temuan antar-tool akurat.

7. **Dataset WAF Real-Time** – Request history dari Active Scan ZAP diekstrak otomatis dan disimpan ke `zap_attack_requests.json` dengan label `attack` untuk digunakan sebagai dataset pengujian ML-WAF (Blok 3).

8. **OpenAPI spec manual untuk Juice Shop** – Juice Shop tidak menyediakan spec lengkap,
   sehingga 15 endpoint representatif didefinisikan manual di `data/openapi_juiceshop.yaml`.

9. **Functional driver tidak crash pada mismatch** – Test case yang gagal dicatat sebagai
   `passed: false` dengan detail, bukan exception yang menghentikan audit.

10. **Traffic hanya ke staging lokal** – URL non-lokal ditolak kecuali flag `--allow-remote`
    diberikan, untuk mencegah audit yang tidak disengaja ke production.

11. **Param field menggunakan alias `in`** – Pydantic model `Param` menyimpan lokasi sebagai
    `location` secara internal, tetapi serialisasi menggunakan alias `"in"` agar sesuai dengan
    format OpenAPI spec.

12. **Modul Ekstraksi Fitur ML-WAF Tunggal (Zero Train-Serve Skew)** – Modul `audit.mlwaf.features` dipakai bersama oleh skrip pelatihan (`train.py`) dan runtime reverse-proxy WAF (`mitmproxy addon`), memastikan vektor fitur yang diekstrak selalu identik urutan dan perhitungannya.

13. **Metodologi CRISP-DM untuk ML-WAF** – Pelatihan mengikuti 6 tahap CRISP-DM: Business Understanding, Data Understanding, Data Preparation (dedup sebelum split, stratified 80:20), Modeling (Decision Tree criterion='entropy' dengan 5-fold CV GridSearchCV hanya di data train), Evaluation (hold-out test set vs baseline), dan Deployment (bundle joblib + confusion matrix PNG + laporan JSON/CSV).

14. **Deduplikasi Sebelum Split** – Untuk mencegah kebocoran data (data leakage), permintaan HTTP dengan string method, URL, query, dan body ternormalisasi yang identik disaring sebelum pembagian train-test.

15. **Fallback Generator Dataset Sintetis** – Jika dataset CSIC 2010 asli belum ditempatkan di `data/csic/`, sistem secara otomatis membuat dataset sintetis HTTP request untuk memverifikasi fungsionalitas pipeline secara end-to-end tanpa error.

16. **Union List Aggregator & Deduplikasi Multitool** – Deduplikasi temuan menggabungkan ZAP dan scanner kedua berdasarkan tuple `(cwe, route, param, method)`. Duplikasi diselesaikan dengan mengambil severity tertinggi dan menandai `tool = "zap+<scanner2>"`. Urutan deterministik stabil berdasarkan tingkat keparahan, route, dan CWE.

17. **Toleransi Pencocokan Ground Truth** – Temuan pemindai dinyatakan cocok dengan entri acuan (*True Positive*) apabila CWE dan route ternormalisasi identik (serta method HTTP). Pencocokan parameter dijadikan opsi toleransi (`--match-param`) agar variasi penamaan parameter antar-tool tidak mendistorsi pengukuran recall.

18. **Scorecard Engine Deterministik (Fungsi Murni)** – Engine scorecard murni berbasis komputasi matematis tanpa I/O jaringan untuk memastikan konsistensi keputusan 100%. Komponen performa yang belum dievaluasi menghasilkan status `INCOMPLETE` (exit code 3).

19. **Kill Switch Protektif** – Pemicu kill switch membatalkan nilai UPRI tinggi jika terdapat kerentanan Critical/High atau error/latensi tinggi pada profil Typical atau Peak. Profil Stress dikecualikan dari pemicu error rate karena bertujuan menguji daya tahan puncak sistem (*breaking point*).

20. **Active Defense Verifier (mitmproxy + ML-WAF Runtime)** – Mitmproxy add-on (`audit/mlwaf/mitm_addon.py`) berjalan sebagai reverse proxy (port 8082), mencegat permintaan HTTP sebelum ke target dan mengklasifikasikan menggunakan model Decision Tree (HTTP 403 Forbidden + header `X-WAF-Decision: blocked` jika anomali/serangan; lolos dengan `X-WAF-Decision: allowed` jika sah). Pengujian real-time memakai data independen (permintaan sah dari registry vs riwayat serangan ZAP/sintetis, tanpa memakai sampel CSIC). Hasil WAF dicatat di `waf.json` dan confusion matrix PNG secara terpisah tanpa mengubah formula $S_{sec}$ UPRI.

21. **Performance Driver (k6) & Resource Monitoring** – Skrip k6 JavaScript digenerasi dinamis dari rute aman Registry (GET dan POST pencarian/idempotent). Menyediakan 4 profil beban (*Typical*, *Peak*, *Stress*, *Spike*) dengan opsi `--scale` dan `--quick` untuk lingkungan laptop berspesifikasi standar. Resource monitor mencuplik penggunaan CPU & memori kontainer via `docker stats` (dinormalisasi ke acuan 2 core / 2 GB), dengan fallback mulus ke `psutil` host jika Docker offline. Target kontainer di-restart dan di-polling healthcheck sebelum tiap profil agar kondisi awal bersih.

## Rumus Scorecard

```
Ssec = max(0, 100 - Σ(Ni × Wi))
  Wi: Critical=100, High=50, Medium=15, Low=5

Platency = ((L - μ) / L) × 100  jika μ < L, else 0  (L = 500ms)

Presource = 100 - max(cpu_pct, mem_pct), clamp 0..100

Pperf = 0.5 × (100 × (1 - ER)) + 0.3 × Platency + 0.2 × Presource

UPRI = 0.6 × Ssec + 0.4 × Pperf

Kill switch aktif jika:
  (a) ≥1 temuan Critical/High di Union List, ATAU
  (b) ER > 0 pada profil Typical/Peak, ATAU
  (c) Platency = 0 pada profil Typical/Peak

Keputusan:
  kill switch aktif ATAU UPRI < 70  → REJECTED (exit 2)
  70 ≤ UPRI < 85                   → CONDITIONAL PASS (exit 1)
  UPRI ≥ 85                        → PASSED (exit 0)
```

## Testing

```bash
pytest -v
```
