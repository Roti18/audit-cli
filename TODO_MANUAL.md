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
  - `feat/mlwaf` (Pelatihan ML-WAF & model.joblib)
  - `feat/scorecard` (Union list aggregator & Scorecard Engine)
  
  URL pembuatan/penggabungan PR:
  - [PR feat/security](https://github.com/Roti18/audit-cli/pull/new/feat/security)
  - [PR feat/mlwaf](https://github.com/Roti18/audit-cli/pull/new/feat/mlwaf)
  - [PR feat/scorecard](https://github.com/Roti18/audit-cli/pull/new/feat/scorecard)

---

## 3. Eksekusi Pemindaian Keamanan Nyata (Live DAST)
Setelah Juice Shop dan ZAP berjalan di Docker, jalankan pemindaian penuh di background:

- [ ] **Jalankan pemindaian keamanan live (latar belakang)**:
  ```powershell
  .\.venv\Scripts\Activate.ps1
  Start-Process -NoNewWindow python -ArgumentList "-m audit.cli security --registry results/run1/registry.json --scanner2 nuclei --out results/live_run --max-minutes 30"
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

## 4. Validasi Ground Truth Kerentanan Juice Shop
Berkas acuan saat ini berisi 15 kerentanan representatif OWASP Juice Shop:

- [ ] **Tinjau berkas acuan**:
  Buka [data/ground_truth_juiceshop.json](file:///D:/semester%205/Metode%20Penelitian/project/data/ground_truth_juiceshop.json).
- [ ] **Sesuaikan dengan fokus skripsi**:
  Jika ada kerentanan tertentu yang disepakati dengan dosen pembimbing (misal fokus pada SQLi dan XSS saja), ubah status `"perlu_verifikasi_manual": false` pada item yang sudah diverifikasi.

---

## 5. Persiapan Dependensi Alat untuk Blok Berikutnya (Performance & WAF Runtime)
Sesuai rancangan proposal, **k6** dan **mitmproxy** dipasang langsung di host (bukan container):

- [ ] **Pasang k6 di Host Windows**:
  Jalankan salah satu perintah:
  ```powershell
  # Menggunakan winget
  winget install k6 --source winget
  
  # Atau menggunakan Chocolatey
  choco install k6
  ```
  Verifikasi ketersediaan:
  ```powershell
  k6 version
  ```
- [ ] **Verifikasi mitmproxy**:
  `mitmproxy` sudah terpasang di virtual environment Python (`.venv`). Verifikasi dengan:
  ```powershell
  .\.venv\Scripts\mitmdump.exe --version
  ```

---

## 6. Ringkasan Perintah Penting (Cheat Sheet)

| Operasi | Perintah PowerShell |
|---|---|
| **Aktivasi Venv** | `.\.venv\Scripts\Activate.ps1` |
| **Jalankan Semua Test** | `pytest -v` (100 tests passed) |
| **Discovery Endpoint** | `audit discover http://localhost:3000 --spec data/openapi_juiceshop.yaml --out results/run1` |
| **Uji Fungsional** | `audit functional --registry results/run1/registry.json` |
| **Security Scan (Quick/Test)** | `audit security --registry results/run1/registry.json --scanner2 nuclei --out results/run1 --max-minutes 1` |
| **Latih Model ML-WAF** | `audit train-waf` |
| **Laporan Metrik DAST** | `audit security-report --run-dir results/sample_run` |
| **Hitung Scorecard (UPRI)** | `audit score --run-dir results/run1 --perf-file results/run1/performance.json` |
