"""Metrik Evaluasi Pemindai Keamanan (Precision, Recall, F-Measure, & Recall Improvement).

Mengevaluasi kinerja:
1. ZAP saja
2. Scanner kedua saja (Arachni/Nuclei)
3. Union List (gabungan terdeduplikasi)

Terhadap Ground Truth kerentanan acuan (data/ground_truth_juiceshop.json).
Menghitung peningkatan Recall (relatif & poin persentase) dengan verifikasi target >= 15%.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import pandas as pd

from audit.schemas import Finding
from audit.security.normalizer import normalize_cwe, normalize_route


def match_finding_to_gt(
    finding: Finding,
    gt_item: dict[str, Any],
    match_param: bool = False,
    match_method: bool = True,
) -> bool:
    """Mencocokkan sebuah temuan pemindai ke entri acuan ground truth.

    Kriteria kecocokan (Toleransi Desain):
    1. CWE identik (misal CWE-89 == CWE-89)
    2. Route ternormalisasi identik (misal /api/Products/1 -> /api/Products/{id})
    3. Method HTTP identik jika match_method=True
    4. Nama parameter opsional jika match_param=True (toleransi nama query/body)
    """
    f_cwe = normalize_cwe(finding.cwe)
    gt_cwe = normalize_cwe(gt_item.get("cwe"))
    if not f_cwe or not gt_cwe or f_cwe != gt_cwe:
        return False

    f_route = normalize_route(finding.route)
    gt_route = normalize_route(gt_item.get("route", ""))
    if f_route != gt_route:
        return False

    if match_method:
        f_method = (finding.method or "GET").upper()
        gt_method = (gt_item.get("method") or "GET").upper()
        if f_method != gt_method:
            return False

    if match_param:
        gt_param = gt_item.get("param")
        if gt_param is not None:
            f_param = (finding.param or "").strip().lower()
            if f_param != str(gt_param).strip().lower():
                return False

    return True


def evaluate_tool_performance(
    findings: list[Finding],
    ground_truth: list[dict[str, Any]],
    match_param: bool = False,
) -> dict[str, Any]:
    """Menghitung TP, FP, FN, Precision, Recall, dan F1 untuk himpunan temuan tertentu."""
    total_gt = len(ground_truth)
    if total_gt == 0:
        return {
            "tp": 0, "fp": len(findings), "fn": 0,
            "precision": 0.0, "recall": 0.0, "f1": 0.0,
            "matched_gt_ids": [],
        }

    # 1. Cari ground truth yang terdeteksi (True Positives)
    matched_gt_ids: set[str] = set()
    finding_matched: list[bool] = [False] * len(findings)

    for gt in ground_truth:
        for idx, f in enumerate(findings):
            if match_finding_to_gt(f, gt, match_param=match_param):
                matched_gt_ids.add(str(gt.get("id")))
                finding_matched[idx] = True

    tp = len(matched_gt_ids)
    fn = total_gt - tp
    fp = sum(1 for matched in finding_matched if not matched)

    precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = float(tp / total_gt) if total_gt > 0 else 0.0
    f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched_gt_ids": sorted(list(matched_gt_ids)),
    }


def compute_security_metrics(
    zap_findings: list[Finding],
    scanner2_findings: list[Finding],
    union_findings: list[Finding],
    ground_truth_path: str | Path = "data/ground_truth_juiceshop.json",
    scanner2_name: str = "nuclei",
    out_dir: str | Path | None = None,
    match_param: bool = False,
) -> dict[str, Any]:
    """Menghitung metrik lengkap untuk ZAP, Scanner kedua, dan Union List."""
    gt_file = Path(ground_truth_path)
    if not gt_file.exists():
        raise FileNotFoundError(f"File Ground Truth tidak ditemukan: {gt_file}")

    ground_truth: list[dict[str, Any]] = json.loads(gt_file.read_text(encoding="utf-8"))

    # Evaluasi masing-masing
    res_zap = evaluate_tool_performance(zap_findings, ground_truth, match_param=match_param)
    res_s2 = evaluate_tool_performance(scanner2_findings, ground_truth, match_param=match_param)
    res_union = evaluate_tool_performance(union_findings, ground_truth, match_param=match_param)

    # Analisis Peningkatan Recall (Improvement)
    rec_zap = res_zap["recall"]
    rec_s2 = res_s2["recall"]
    rec_union = res_union["recall"]

    best_single_rec = max(rec_zap, rec_s2)
    best_single_name = "ZAP" if rec_zap >= rec_s2 else scanner2_name

    # 1. Poin Persentase (Percentage Points Difference)
    pp_vs_best = round((rec_union - best_single_rec) * 100, 2)
    pp_vs_zap = round((rec_union - rec_zap) * 100, 2)
    pp_vs_s2 = round((rec_union - rec_s2) * 100, 2)

    # 2. Peningkatan Relatif (%)
    rel_vs_best = round(((rec_union - best_single_rec) / best_single_rec * 100), 2) if best_single_rec > 0 else 0.0
    rel_vs_zap = round(((rec_union - rec_zap) / rec_zap * 100), 2) if rec_zap > 0 else 0.0
    rel_vs_s2 = round(((rec_union - rec_s2) / rec_s2 * 100), 2) if rec_s2 > 0 else 0.0

    target_pass_relative = rel_vs_best >= 15.0
    target_pass_pp = pp_vs_best >= 15.0

    # Buat DataFrame perbandingan
    rows = [
        {
            "Komponen": "ZAP (Pemindai Tunggal)",
            "Total Temuan": len(zap_findings),
            "TP": res_zap["tp"],
            "FP": res_zap["fp"],
            "FN": res_zap["fn"],
            "Presisi": f"{res_zap['precision'] * 100:.2f}%",
            "Recall": f"{res_zap['recall'] * 100:.2f}%",
            "F1-Score": f"{res_zap['f1'] * 100:.2f}%",
        },
        {
            "Komponen": f"{scanner2_name.capitalize()} (Pemindai Kedua)",
            "Total Temuan": len(scanner2_findings),
            "TP": res_s2["tp"],
            "FP": res_s2["fp"],
            "FN": res_s2["fn"],
            "Presisi": f"{res_s2['precision'] * 100:.2f}%",
            "Recall": f"{res_s2['recall'] * 100:.2f}%",
            "F1-Score": f"{res_s2['f1'] * 100:.2f}%",
        },
        {
            "Komponen": "Union List (Agregasi DAST)",
            "Total Temuan": len(union_findings),
            "TP": res_union["tp"],
            "FP": res_union["fp"],
            "FN": res_union["fn"],
            "Presisi": f"{res_union['precision'] * 100:.2f}%",
            "Recall": f"{res_union['recall'] * 100:.2f}%",
            "F1-Score": f"{res_union['f1'] * 100:.2f}%",
        },
    ]
    df_metrics = pd.DataFrame(rows)

    metrics_payload = {
        "ground_truth_file": str(gt_file),
        "total_ground_truth": len(ground_truth),
        "disclaimer": "Catatan: Nilai metrik dihitung relatif terhadap ground truth benchmark yang didefinisikan (data/ground_truth_juiceshop.json).",
        "evaluations": {
            "zap": res_zap,
            "scanner2": res_s2,
            "union": res_union,
        },
        "recall_improvement": {
            "best_single_scanner": best_single_name,
            "best_single_recall": best_single_rec,
            "union_recall": rec_union,
            "percentage_points": {
                "vs_best_single": pp_vs_best,
                "vs_zap": pp_vs_zap,
                "vs_scanner2": pp_vs_s2,
            },
            "relative_percent": {
                "vs_best_single": rel_vs_best,
                "vs_zap": rel_vs_zap,
                "vs_scanner2": rel_vs_s2,
            },
            "target_threshold": ">= 15%",
            "target_passed_relative": target_pass_relative,
            "target_passed_percentage_points": target_pass_pp,
        },
    }

    # Simpan output jika out_dir diberikan
    if out_dir is not None:
        p_out = Path(out_dir)
        p_out.mkdir(parents=True, exist_ok=True)

        json_path = p_out / "security_metrics.json"
        json_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

        csv_path = p_out / "security_metrics.csv"
        df_metrics.to_csv(csv_path, index=False)

    return metrics_payload
