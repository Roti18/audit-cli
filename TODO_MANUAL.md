# Checklist Tindakan Manual (Action Items) – Audit CLI Framework

Dokumen ini merangkum seluruh langkah operasional, integrasi naskah Bab IV skripsi, dan verifikasi akhir yang **harus dilakukan oleh mahasiswa** di host Windows 11.

---

## 1. Status Penyelesaian Framework (100% Selesai & Terverifikasi)

| Komponen / Artefak | Status | Bukti / Direktori |
|---|:---:|---|
| **Unit Test Suite** | **121/121 Lulus (100%)** | `tests/` (dievaluasi via `pytest -v`) |
| **Skenario Jalur Sukses (Clean API)** | **PASSED (Exit Code: 0)** | `results/clean_api/` ($\text{UPRI} = 94.41$, Kill Switch = False) |
| **Skenario Target Rentan (Juice Shop)** | **REJECTED (Exit Code: 2)** | `results/juiceshop/` ($\text{UPRI} = 31.8$, Kill Switch = True) |
| **Paket Bukti Kuantitatif Bab IV** | **Lengkap** | `results/bab4/` (5 Tabel Markdown/CSV + 4 Grafik PNG) |
| **Laporan Audit Mandiri (Zero CDN)** | **Tersedia** | `results/clean_api/report.html` & `results/juiceshop/report.html` |

---

## 2. Checklist Integrasi Naskah Bab IV Skripsi

Lakukan langkah-langkah berikut untuk memasukkan data hasil eksperimen ke dalam draf naskah skripsi:

### A. Tangkapan Layar Laporan Visual (*Visual Report Screenshots*)
Buka berkas laporan HTML mandiri menggunakan browser:
- [ ] **Buka Laporan Jalur Sukses (Clean API)**:
  ```powershell
  start results\clean_api\report.html
  ```
  *Ambil screenshot*: Banner hijau **PASSED**, nilai UPRI (94.41), rincian $S_{\text{sec}} = 100$, $P_{\text{perf}} = 86.03$, dan tabel performa k6 bersih tanpa error. Simpan untuk bukti Subbab 4.5.
- [ ] **Buka Laporan Target Rentan (Juice Shop)**:
  ```powershell
  start results\juiceshop\report.html
  ```
  *Ambil screenshot*: Banner merah **REJECTED**, pemicu *Kill Switch* aktif (Critical SQLi / High XSS), nilai UPRI rendah (31.8), dan tabel temuan kerentanan *Union List*. Simpan untuk bukti Subbab 4.5.

### B. Salin Tabel Kuantitatif & Gambar Grafik Bab IV
Seluruh artefak kuantitatif telah diformat dalam Markdown (`.md`), spreadsheet (`.csv`), dan visualisasi resolusi tinggi (`.png`) di folder [results/bab4/](file:///D:/semester%205/Metode%20Penelitian/project/results/bab4):

- [ ] **Subbab 4.1 (RQ1 - Endpoint Discovery & Schema Parsing)**:
  - Buka `results/bab4/table_rq1_discovery.md` (atau `.csv`).
  - Salin tabel perbandingan parsing rate (100% keberhasilan parsing OpenAPI Juice Shop & Clean API, resolusi skema bersarang).
- [ ] **Subbab 4.2 (RQ2 - Peningkatan Recall DAST Multi-Tool)**:
  - Buka `results/bab4/table_rq2_dast_recall.md` (Tabel metrik ZAP vs Nuclei vs Union List).
  - Masukkan gambar grafik komparasi: `results/bab4/graph_rq2_recall_comparison.png` (menunjukkan peningkatan recall dari pemindai tunggal 33%–40% menjadi 60% pada Union List).
- [ ] **Subbab 4.3 (RQ3 - Efektivitas Deteksi ML-WAF CRISP-DM)**:
  - Buka `results/bab4/table_rq3_mlwaf_accuracy.md`.
  - Salin tabel perbandingan metrik: Baseline Filter Kata Kunci (Akurasi 46.71%) vs Decision Tree Hold-out CSIC 2010 (Akurasi 77.91%, $F_1 = 81.51\%$) vs Mitigasi Real-Time mitmproxy (Akurasi 92.00%, $F_1 = 91.50\%$, FPR 4.00%).
- [ ] **Subbab 4.4 (RQ4 - Profiling Beban & Utilisasi Sumber Daya API)**:
  - Buka `results/bab4/table_rq4_performance.md`.
  - Masukkan gambar grafik latensi: `results/bab4/graph_rq4_latency_profiles.png` (Latensi Avg vs P95 terhadap batas $L = 500\text{ ms}$).
  - Masukkan gambar grafik throughput: `results/bab4/graph_rq4_rps_profiles.png`.
- [ ] **Subbab 4.5 (RQ5 - Konsistensi Mesin Scorecard & Komparasi Dua Target)**:
  - Buka `results/bab4/table_rq5_scorecard_matrix.md` (Matriks 11 skenario pengujian batas dan status *Kill Switch*).
  - Masukkan gambar grafik perbandingan UPRI: `results/bab4/graph_rq5_upri_comparison.png` (Komparasi Ideal 97.6 vs Clean API 98.5 vs Juice Shop 31.8).

---

## 3. Manajemen Branch & Pull Request di GitHub

Seluruh kode framework telah dibagi rapi sesuai tahapan modul blok. Buka GitHub repositori dan tinjau PR berikut:

- [ ] [PR feat/security](https://github.com/Roti18/audit-cli/pull/new/feat/security) – Blok DAST (ZAP + Nuclei + Normalizer)
- [ ] [PR feat/mlwaf](https://github.com/Roti18/audit-cli/pull/new/feat/mlwaf) – Blok Pelatihan ML-WAF CRISP-DM
- [ ] [PR feat/scorecard](https://github.com/Roti18/audit-cli/pull/new/feat/scorecard) – Blok Union List & Scorecard Engine
- [ ] [PR feat/waf-perf](https://github.com/Roti18/audit-cli/pull/new/feat/waf-perf) – Blok Active Defense mitmproxy & Driver k6
- [ ] [PR feat/report](https://github.com/Roti18/audit-cli/pull/new/feat/report) – Blok 3 Final: Report Generator, E2E CLI Pipeline, Clean API, dan Paket Bukti Bab IV.

---

## 4. Demonstrasi Langsung (Live Demo) Saat Sidang / Bimbingan

Jika ingin menjalankan demonstrasi langsung di hadapan dosen pembimbing atau penguji:

```powershell
# Langkah 1: Buka terminal PowerShell di folder proyek dan aktifkan venv
.\.venv\Scripts\Activate.ps1

# Langkah 2: Pastikan kontainer docker menyala
docker compose up -d

# Langkah 3: Jalankan demonstrasi jalur kelulusan PASSED (durasi ~1 menit)
audit http://localhost:5000 --spec data/openapi_clean_api.yaml --run-id demo_clean --quick --scale 0.1

# Langkah 4: Tampilkan status exit code di PowerShell
echo $LASTEXITCODE    # Menampilkan: 0 (PASSED)

# Langkah 5: Buka laporan interaktif hasil demo
start results\demo_clean\report.html
```

---

## 5. Cheat Sheet Perintah Utama

| Operasi | Perintah PowerShell |
|---|---|
| **Aktivasi Lingkungan** | `.\.venv\Scripts\Activate.ps1` |
| **Eksekusi 121 Unit Test** | `pytest -v` |
| **Audit Lengkap (Target Bersih)** | `audit http://localhost:5000 --spec data/openapi_clean_api.yaml --run-id clean_api --quick --scale 0.1` |
| **Audit Lengkap (Target Rentan)** | `audit http://localhost:3000 --spec data/openapi_juiceshop.yaml --run-id juiceshop --quick --scale 0.1` |
| **Regenerasi Laporan HTML** | `audit report --run-dir results/clean_api` |
| **Regenerasi Paket Bukti Bab IV** | `python scripts/make_chapter4_tables.py results results/bab4` |
