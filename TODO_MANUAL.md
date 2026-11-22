# Checklist Tindakan Manual (Action Items) – Audit CLI Framework

Dokumen ini merangkum seluruh langkah operasional yang **harus dilakukan secara manual** oleh pengguna di host Windows 11 untuk menyelesaikan pengujian *end-to-end* skripsi.

---

## 1. Lingkungan Docker & Target Staging (Prioritas 1)
Kode framework saat ini sudah 100% toleran terhadap kegagalan alat eksternal (*fault-tolerant*), namun untuk mendapatkan data audit nyata, container target dan scanner harus dijalankan:

- [ ] **Buka / Jalankan Docker Desktop di Windows 11**:
  Pastikan Docker Engine berstatus *Running*.
- [ ] **Jalankan container lab audit**:
  Buka terminal PowerShell di folder proyek dan jalankan:
  ```powershell
  docker compose up -d
  ```
- [ ] **Verifikasi status kesehatan container**:
  ```powershell
  docker compose ps
  curl http://localhost:3000/                           # Juice Shop harus merespons HTML
  curl http://localhost:8080/JSON/core/view/version/    # ZAP harus merespons JSON versi
  docker compose exec nuclei nuclei --version           # Nuclei harus terpasang
  ```

---

## 2. Manajemen Branch & Git di GitHub
Pekerjaan telah diunggah ke branch terpisah sesuai tahapan blok:

- [ ] **Tinjau dan Merge Pull Request di GitHub**:
  - `feat/security` (Security driver & normalizer)
  - `feat/mlwaf` (Pelatihan ML-WAF CRISP-DM & model.joblib)
  - `feat/scorecard` (Union list aggregator & Scorecard Engine)
  - `feat/waf-perf` (Active Defense Verifier mitmproxy + Performance Driver k6)
  
  URL pembuatan/penggabungan PR:
  - [PR feat/security](https://github.com/Roti18/audit-cli/pull/new/feat/security)
  - [PR feat/mlwaf](https://github.com/Roti18/audit-cli/pull/new/feat/mlwaf)
  - [PR feat/scorecard](https://github.com/Roti18/audit-cli/pull/new/feat/scorecard)
  - [PR feat/waf-perf](https://github.com/Roti18/audit-cli/pull/new/feat/waf-perf)

---

## 3. Eksekusi Pemindaian Keamanan Nyata (Live DAST)
Setelah Juice Shop dan ZAP berjalan di Docker, jalankan pemindaian penuh di background:

- [ ] **Jalankan pemindaian keamanan live (latar belakang)**:
  ```powershell
  .\.venv\Scripts\Activate.ps1
  python -m audit.cli security --registry results/run1/registry.json --scanner2 nuclei --out results/live_run --max-minutes 30
  ```
- [ ] **Pantau progres ascan dan log secara real-time**:
  ```powershell
  Get-Content -Wait -Tail 20 results\live_run\security.log
  ```
- [ ] **Cetak laporan metrik keamanan setelah scan selesai**:
  ```powershell
  python -m audit.cli security-report --run-dir results/live_run
  ```

---

## 4. Eksekusi Verifikasi Active Defense (ML-WAF Runtime)
Menguji keandalan pemblokiran serangan injeksi secara real-time lewat mitmproxy reverse proxy:

- [ ] **Jalankan WAF Verifier**:
  ```powershell
  python -m audit.cli waf --registry results/run1/registry.json --out results/live_waf --proxy-port 8082
  ```
- [ ] **Tinjau visualisasi Matriks Konfusi**:
  Buka berkas grafik yang dihasilkan: `results/live_waf/waf_confusion_matrix.png` dan berkas log keputusan `results/live_waf/waf_decisions.jsonl`.

---

## 5. Eksekusi Pengujian Beban & Performa (k6)
k6 (v1.5.0) telah terdeteksi langsung di host. Jalankan pengujian performa API:

- [ ] **Dry Run / Pengujian Cepat (Rekomendasi laptop spek standar)**:
  ```powershell
  python -m audit.cli perf --registry results/run1/registry.json --out results/live_perf --quick --scale 0.1
  ```
- [ ] **Full Stress & Spike Run (Sesuai proposal: 100/500/1000 VU)**:
  ```powershell
  python -m audit.cli perf --registry results/run1/registry.json --out results/live_perf --scale 1.0
  ```
- [ ] **Periksa metrik performa**:
  Buka `results/live_perf/performance.json` dan CSV resource sampling `results/live_perf/resource_stats_typical.csv`.

---

## 6. Hitung Skor Kesiapan Produksi Final (Scorecard & UPRI)
Setelah data keamanan DAST dan data performa terkumpul:

- [ ] **Kalkulasi Scorecard UPRI**:
  ```powershell
  python -m audit.cli score --run-dir results/live_run --perf-file results/live_perf/performance.json
  ```
- [ ] **Verifikasi status Kill Switch & Keputusan Akhir**:
  Periksa apakah sistem mendapatkan status **PASSED (Exit Code 0)**, **CONDITIONAL PASS (Exit Code 1)**, atau **REJECTED (Exit Code 2)**.

---

## 7. Validasi Ground Truth Kerentanan Juice Shop
Berkas acuan saat ini berisi 15 kerentanan representatif OWASP Juice Shop:

- [ ] **Tinjau berkas acuan**:
  Buka [data/ground_truth_juiceshop.json](file:///D:/semester%205/Metode%20Penelitian/project/data/ground_truth_juiceshop.json).
- [ ] **Sesuaikan dengan fokus skripsi**:
  Jika ada kerentanan tertentu yang disepakati dengan dosen pembimbing (misal fokus pada SQLi dan XSS saja), ubah status `"perlu_verifikasi_manual": false` pada item yang sudah diverifikasi.

---

## 8. Ringkasan Perintah Penting (Cheat Sheet)

| Operasi | Perintah PowerShell |
|---|---|
| **Aktivasi Venv** | `.\.venv\Scripts\Activate.ps1` |
| **Jalankan Semua Test** | `.\.venv\Scripts\pytest -v` (111 tests passed) |
| **Bantuan CLI Lengkap** | `python -m audit.cli --help` |
| **Uji Beban Cepat (k6)** | `python -m audit.cli perf --registry results/run1/registry.json --quick --scale 0.1` |
| **Uji WAF Real-time** | `python -m audit.cli waf --registry results/run1/registry.json --proxy-port 8082` |
| **Scorecard Final** | `python -m audit.cli score --run-dir results/live_run --perf-file results/live_perf/performance.json` |
