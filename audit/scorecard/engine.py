"""Scorecard Engine – Evaluasi Kesiapan Produksi API & Perhitungan UPRI.

Murni fungsi matematis tanpa I/O jaringan, deterministik, dan teruji penuh:
- Ssec: Skor keamanan berdasarkan bobot temuan Union List (Critical=100, High=50, Medium=15, Low=5).
- Platency: Skor latensi terhadap ambang batas L = 500 ms.
- Presource: Skor efisiensi resource CPU & Memory (dinormalisasi 2 core & 2 GB).
- Pperf: Skor performa gabungan (0.5*(100*(1-ER)) + 0.3*Platency + 0.2*Presource).
- UPRI: Unified Production Readiness Index (0.6*Ssec + 0.4*Pperf).
- Kill Switch: Proteksi keras (override UPRI) jika ada temuan Critical/High atau error/latensi tinggi di Typical/Peak.
- Decision: PASSED (exit 0), CONDITIONAL PASS (exit 1), REJECTED (exit 2), INCOMPLETE (exit 3).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from audit.schemas import Finding, Scorecard, Severity, save_json

# Bobot Pengurangan Nilai Keamanan (Ssec)
SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.critical: 100.0,
    Severity.high: 50.0,
    Severity.medium: 15.0,
    Severity.low: 5.0,
    Severity.info: 0.0,
}

# Batas Latensi Maksimal (ms)
L_LATENCY_THRESHOLD_MS: float = 500.0


# ---------------------------------------------------------------------------
# 1. Perhitungan Ssec (Security Score)
# ---------------------------------------------------------------------------
def compute_ssec(findings: list[Finding]) -> tuple[float, dict[str, Any]]:
    """Menghitung skor keamanan Ssec dari temuan Union List yang terdeduplikasi.

    Rumus: Ssec = max(0, 100 - sum(N_i * W_i))
    W: Critical=100, High=50, Medium=15, Low=5
    """
    counts = {
        Severity.critical: 0,
        Severity.high: 0,
        Severity.medium: 0,
        Severity.low: 0,
        Severity.info: 0,
    }
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total_deduction = sum(counts[sev] * SEVERITY_WEIGHTS[sev] for sev in counts)
    ssec = max(0.0, 100.0 - total_deduction)

    breakdown = {
        "critical_count": counts[Severity.critical],
        "high_count": counts[Severity.high],
        "medium_count": counts[Severity.medium],
        "low_count": counts[Severity.low],
        "info_count": counts[Severity.info],
        "total_deduction": round(total_deduction, 2),
        "raw_ssec": round(ssec, 2),
    }
    return round(ssec, 2), breakdown


# ---------------------------------------------------------------------------
# 2. Perhitungan Komponen Performa (Platency & Presource)
# ---------------------------------------------------------------------------
def compute_platency(mu_ms: float, L: float = L_LATENCY_THRESHOLD_MS) -> float:
    """Menghitung skor latensi Platency.

    Rumus: ((L - mu)/L)*100 jika mu < L, else 0.
    """
    if mu_ms >= L:
        return 0.0
    if mu_ms <= 0.0:
        return 100.0
    score = ((L - mu_ms) / L) * 100.0
    return round(max(0.0, min(100.0, score)), 2)


def compute_presource(cpu_pct: float, mem_pct: float) -> float:
    """Menghitung skor pemakaian sumber daya Presource.

    Rumus: 100 - max(cpu_pct, mem_pct), dibatasi 0..100.
    """
    max_usage = max(cpu_pct, mem_pct)
    score = 100.0 - max_usage
    return round(max(0.0, min(100.0, score)), 2)


# ---------------------------------------------------------------------------
# 3. Perhitungan Pperf (Performance Score)
# ---------------------------------------------------------------------------
def compute_pperf(
    profile_data: dict[str, Any],
    L: float = L_LATENCY_THRESHOLD_MS,
) -> tuple[float, dict[str, Any]]:
    """Menghitung skor performa Pperf untuk satu profil pengujian.

    Rumus: Pperf = 0.5*(100*(1-ER)) + 0.3*Platency + 0.2*Presource
    ER adalah proporsi 0..1 (bukan persen utuh).
    """
    er = float(profile_data.get("error_rate", 0.0))
    # Otomatis normalisasi jika ER diberikan dalam format persen (misal 5.0 -> 0.05)
    if er > 1.0:
        er = er / 100.0
    er = max(0.0, min(1.0, er))

    avg_lat = float(profile_data.get("latency_avg_ms", profile_data.get("avg_latency_ms", 0.0)))
    cpu = float(profile_data.get("cpu_pct_peak", profile_data.get("peak_cpu_pct", 0.0)))
    mem = float(profile_data.get("mem_pct_peak", profile_data.get("peak_mem_pct", 0.0)))

    p_error = 100.0 * (1.0 - er)
    p_latency = compute_platency(avg_lat, L=L)
    p_resource = compute_presource(cpu, mem)

    pperf = 0.5 * p_error + 0.3 * p_latency + 0.2 * p_resource
    pperf_clamped = max(0.0, min(100.0, pperf))

    breakdown = {
        "error_rate": er,
        "p_error": round(p_error, 2),
        "avg_latency_ms": avg_lat,
        "p_latency": p_latency,
        "cpu_pct_peak": cpu,
        "mem_pct_peak": mem,
        "p_resource": p_resource,
        "pperf": round(pperf_clamped, 2),
    }
    return round(pperf_clamped, 2), breakdown


def aggregate_pperf(
    profiles: dict[str, dict[str, Any]] | list[dict[str, Any]],
    L: float = L_LATENCY_THRESHOLD_MS,
) -> tuple[float, dict[str, Any]]:
    """Menghitung Pperf gabungan (rata-rata dari profil typical, peak, dan stress).
    Profil spike dievaluasi dan dicatat terpisah.
    """
    profile_dict: dict[str, dict[str, Any]] = {}
    if isinstance(profiles, list):
        for p in profiles:
            p_name = p.get("profile", "unknown").lower()
            profile_dict[p_name] = p
    elif isinstance(profiles, dict):
        profile_dict = {k.lower(): v for k, v in profiles.items()}

    evaluated_breakdowns: dict[str, Any] = {}
    pperf_values: list[float] = []

    # Profil inti penyusun Pperf final
    core_profiles = ["typical", "peak", "stress"]
    for prof_name in core_profiles:
        if prof_name in profile_dict:
            score, bdown = compute_pperf(profile_dict[prof_name], L=L)
            evaluated_breakdowns[prof_name] = bdown
            pperf_values.append(score)

    if pperf_values:
        final_pperf = sum(pperf_values) / len(pperf_values)
    else:
        final_pperf = 0.0

    # Evaluasi spike terpisah jika ada
    if "spike" in profile_dict:
        s_score, s_bdown = compute_pperf(profile_dict["spike"], L=L)
        evaluated_breakdowns["spike"] = s_bdown

    return round(final_pperf, 2), evaluated_breakdowns


# ---------------------------------------------------------------------------
# 4. Perhitungan UPRI (Unified Production Readiness Index)
# ---------------------------------------------------------------------------
def compute_upri(ssec: float, pperf: float) -> float:
    """Menghitung UPRI.

    Rumus: UPRI = 0.6*Ssec + 0.4*Pperf
    """
    upri = 0.6 * ssec + 0.4 * pperf
    return round(max(0.0, min(100.0, upri)), 2)


# ---------------------------------------------------------------------------
# 5. Evaluasi Kill Switch (Override Logic)
# ---------------------------------------------------------------------------
def evaluate_kill_switch(
    findings: list[Finding],
    profiles: dict[str, dict[str, Any]] | list[dict[str, Any]],
    L: float = L_LATENCY_THRESHOLD_MS,
) -> tuple[bool, list[str]]:
    """Mengevaluasi pemicu Kill Switch sesuai proposal:
    (a) Ada >= 1 temuan Critical atau High di Union List
    (b) ER > 0 pada profil Typical atau Peak
    (c) Latensi rata-rata >= L (Platency = 0) pada profil Typical atau Peak

    Catatan: ER > 0 hanya di profil Stress TIDAK memicu kill switch.
    """
    reasons: list[str] = []

    # Kondisi (a): Temuan Critical atau High
    crit_count = sum(1 for f in findings if f.severity == Severity.critical)
    high_count = sum(1 for f in findings if f.severity == Severity.high)

    if crit_count > 0:
        reasons.append(f"Ditemukan {crit_count} kerentanan dengan tingkat keparahan Critical pada Union List.")
    if high_count > 0:
        reasons.append(f"Ditemukan {high_count} kerentanan dengan tingkat keparahan High pada Union List.")

    # Normalisasi dictionary profil
    profile_dict: dict[str, dict[str, Any]] = {}
    if isinstance(profiles, list):
        for p in profiles:
            p_name = p.get("profile", "unknown").lower()
            profile_dict[p_name] = p
    elif isinstance(profiles, dict):
        profile_dict = {k.lower(): v for k, v in profiles.items()}

    # Kondisi (b) & (c): Profil Typical & Peak
    for prof_name in ("typical", "peak"):
        if prof_name in profile_dict:
            p_data = profile_dict[prof_name]
            er = float(p_data.get("error_rate", 0.0))
            if er > 1.0:
                er = er / 100.0

            if er > 0.0:
                reasons.append(
                    f"Error rate terdeteksi sebesar {er * 100:.2f}% pada profil beban '{prof_name.capitalize()}' (harus 0%)."
                )

            lat = float(p_data.get("latency_avg_ms", p_data.get("avg_latency_ms", 0.0)))
            if lat >= L:
                reasons.append(
                    f"Latensi rata-rata ({lat:.1f} ms) melampaui batas maksimal {L} ms pada profil beban '{prof_name.capitalize()}'."
                )

    triggered = len(reasons) > 0
    return triggered, reasons


# ---------------------------------------------------------------------------
# 6. Keputusan Akhir (Decision & Exit Codes)
# ---------------------------------------------------------------------------
def decide(
    upri: float,
    kill_switch_triggered: bool,
    performance_evaluated: bool = True,
) -> tuple[str, int]:
    """Menentukan status kelayakan rilis produksi dan exit code CLI:
    - INCOMPLETE (exit code 3): Data performa belum dievaluasi
    - REJECTED (NOT READY, exit code 2): Kill switch aktif ATAU UPRI < 70
    - CONDITIONAL PASS (exit code 1): 70 <= UPRI < 85 (tanpa kill switch)
    - PASSED (READY TO PROD, exit code 0): UPRI >= 85 (tanpa kill switch)
    """
    if not performance_evaluated:
        return "INCOMPLETE", 3

    if kill_switch_triggered or upri < 70.0:
        return "REJECTED", 2
    elif 70.0 <= upri < 85.0:
        return "CONDITIONAL PASS", 1
    else:  # upri >= 85.0
        return "PASSED", 0


# ---------------------------------------------------------------------------
# 7. Orkestrator Scorecard Terpadu
# ---------------------------------------------------------------------------
def build_scorecard(
    run_id: str,
    findings: list[Finding],
    profiles: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
    out_dir: str | Path | None = None,
    allow_skip_perf: bool = False,
) -> Scorecard:
    """Menjalankan evaluasi menyeluruh dan menghasilkan objek Scorecard."""
    ssec, ssec_breakdown = compute_ssec(findings)

    perf_evaluated = profiles is not None and len(profiles) > 0
    if not perf_evaluated and not allow_skip_perf:
        # Performa dilewati tanpa override -> INCOMPLETE
        decision, exit_code = "INCOMPLETE", 3
        pperf = 0.0
        pperf_breakdown: dict[str, Any] = {}
        upri = 0.0
        kill_triggered, kill_reasons = False, ["Data uji performa (k6) belum dievaluasi."]
    else:
        pperf, pperf_breakdown = aggregate_pperf(profiles or {})
        upri = compute_upri(ssec, pperf)
        kill_triggered, kill_reasons = evaluate_kill_switch(findings, profiles or {})
        decision, exit_code = decide(upri, kill_triggered, performance_evaluated=perf_evaluated or allow_skip_perf)

    scorecard = Scorecard(
        run_id=run_id,
        ssec=ssec,
        pperf=pperf,
        upri=upri,
        kill_switch=kill_triggered,
        kill_reasons=kill_reasons,
        decision=decision,
        exit_code=exit_code,
    )

    if out_dir is not None:
        p_out = Path(out_dir)
        p_out.mkdir(parents=True, exist_ok=True)
        save_json(scorecard, p_out / "scorecard.json")

    return scorecard
