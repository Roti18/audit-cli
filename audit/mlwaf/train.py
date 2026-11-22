"""Modul Pelatihan ML-WAF Decision Tree menggunakan metodologi CRISP-DM.

Tahapan CRISP-DM:
1. Business Understanding  : Proteksi API terhadap serangan injeksi berbasis HTTP.
2. Data Understanding      : Karakteristik distribusi dataset CSIC 2010 (panjang, kelas normal vs anomali).
3. Data Preparation        : Parsing raw HTTP, deduplikasi sebelum split, normalisasi, ekstraksi fitur, stratified 80:20 split.
4. Modeling                : DecisionTreeClassifier (criterion='entropy') dengan 5-Fold Stratified GridSearchCV.
5. Evaluation              : Metrik hold-out (Akurasi, Presisi, Recall, F1, FPR), Confusion Matrix, perbandingan Baseline.
6. Deployment              : Ekspor model.joblib, visualisasi matriks konfusi PNG, dan laporan JSON/CSV.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.tree import DecisionTreeClassifier

from audit.mlwaf.features import (
    extract_features,
    feature_names,
    generate_synthetic_csic_dataset,
    is_attack_baseline,
    normalize,
    parse_raw_requests,
)

logger = logging.getLogger("audit.mlwaf.train")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%H:%M:%S")


# ---------------------------------------------------------------------------
# Evaluasi pada Kumpulan Permintaan HTTP (Real-Time Testing Hook)
# ---------------------------------------------------------------------------
def evaluate_on_requests(
    model_or_bundle: Any,
    requests: list[dict[str, Any]],
    expected_label: int = 1,
) -> dict[str, Any]:
    """Mengevaluasi model pada daftar permintaan HTTP arbitrer (misal dari ZAP attack history)."""
    if isinstance(model_or_bundle, dict) and "model" in model_or_bundle:
        model = model_or_bundle["model"]
    else:
        model = model_or_bundle

    if not requests:
        return {"total": 0, "blocked": 0, "allowed": 0, "detection_rate": 0.0}

    features_list = [
        extract_features(r.get("method", "GET"), r.get("url", "/"), r.get("query", ""), r.get("body", ""))
        for r in requests
    ]
    X = np.array(features_list)
    preds = model.predict(X)

    total = len(preds)
    blocked = int(np.sum(preds == 1))
    allowed = int(np.sum(preds == 0))
    detection_rate = round(float(blocked / total), 4) if total > 0 else 0.0

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "detection_rate": detection_rate,
        "expected_label": expected_label,
    }


# ---------------------------------------------------------------------------
# Visualisasi Confusion Matrix
# ---------------------------------------------------------------------------
def _save_confusion_matrix_plot(cm: np.ndarray, out_path: Path) -> None:
    """Simpan grafik Confusion Matrix menggunakan matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.figure(figsize=(6, 5))
        plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
        plt.title("ML-WAF Decision Tree - Confusion Matrix", fontsize=12, pad=12)
        plt.colorbar()

        classes = ["Normal (0)", "Malicious (1)"]
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

        plt.ylabel("True Label", fontsize=11)
        plt.xlabel("Predicted Label", fontsize=11)
        plt.tight_layout()

        out_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out_path, dpi=200)
        plt.close()
        logger.info(f"Confusion matrix disimpan ke {out_path}")
    except Exception as exc:
        logger.warning(f"Gagal membuat visualisasi matplotlib: {exc}")


# ---------------------------------------------------------------------------
# Pipeline Pelatihan Utama (CRISP-DM)
# ---------------------------------------------------------------------------
def train_mlwaf(
    data_dir: str | Path = "data/csic",
    model_output: str | Path = "audit/mlwaf/model.joblib",
    results_dir: str | Path = "results",
) -> dict[str, Any]:
    """Menjalankan seluruh tahapan CRISP-DM untuk melatih model ML-WAF Decision Tree."""
    data_path = Path(data_dir)
    res_path = Path(results_dir)
    res_path.mkdir(parents=True, exist_ok=True)
    model_path = Path(model_output)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    print("======================================================================")
    print("   CRISP-DM STAGE 1: BUSINESS UNDERSTANDING")
    print("======================================================================")
    print("Tujuan Bisnis : Membangun modul Web Application Firewall (ML-WAF) berbasis")
    print("                Decision Tree untuk memblokir serangan injeksi (SQLi, XSS, CMDi,")
    print("                Path Traversal) dengan target akurasi >= 90% pada hold-out test set.")
    print("Metrik Kunci  : Akurasi, Presisi, Recall, F1-Score, dan False Positive Rate (FPR).")
    print("----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # TAHAP 2: DATA UNDERSTANDING
    # -----------------------------------------------------------------------
    print("======================================================================")
    print("   CRISP-DM STAGE 2: DATA UNDERSTANDING")
    print("======================================================================")

    # Cek ketersediaan dataset
    csic_files = list(data_path.glob("*.txt")) + list(data_path.glob("*.csv"))
    is_synthetic = False

    if not csic_files:
        print(f"[PERINGATAN] Dataset CSIC 2010 tidak ditemukan di folder '{data_path}'.")
        print(">> Mengaktifkan FALLBACK: Membuat dataset SINTETIS untuk menguji seluruh pipeline...")
        generate_synthetic_csic_dataset(data_path)
        is_synthetic = True

    # Muat file
    samples: list[dict[str, Any]] = []

    # Format Kaggle CSV
    csv_files = list(data_path.glob("*.csv"))
    if csv_files:
        print(f"Memuat dataset dari format CSV: {csv_files[0].name}...")
        csv_samples = parse_raw_requests(csv_files[0])
        samples.extend(csv_samples)
    else:
        # Format Raw CSIC .txt
        train_norm = data_path / "normalTrafficTraining.txt"
        test_norm = data_path / "normalTrafficTest.txt"
        test_anom = data_path / "anomalousTrafficTest.txt"

        if train_norm.exists():
            for r in parse_raw_requests(train_norm):
                r["label"] = 0
                samples.append(r)
        if test_norm.exists():
            for r in parse_raw_requests(test_norm):
                r["label"] = 0
                samples.append(r)
        if test_anom.exists():
            for r in parse_raw_requests(test_anom):
                r["label"] = 1
                samples.append(r)

    total_loaded = len(samples)
    count_normal = sum(1 for s in samples if s.get("label", 0) == 0)
    count_attack = sum(1 for s in samples if s.get("label", 0) == 1)

    print(f"Total Sampel Terbaca : {total_loaded}")
    print(f"  - Sampel Normal (0)   : {count_normal} ({count_normal / max(total_loaded, 1) * 100:.1f}%)")
    print(f"  - Sampel Anomali (1)  : {count_attack} ({count_attack / max(total_loaded, 1) * 100:.1f}%)")
    if is_synthetic:
        print("  [CATATAN: Dataset ini SINTETIS dan hanya digunakan untuk verifikasi alur kerja]")

    # Statistik Distribusi Panjang Request
    lengths = [len(s.get("url", "")) + len(s.get("query", "")) + len(s.get("body", "")) for s in samples]
    if lengths:
        print(f"Distribusi Panjang Request:")
        print(f"  - Min    : {min(lengths)} karakter")
        print(f"  - Mean   : {np.mean(lengths):.1f} karakter")
        print(f"  - Median : {np.median(lengths):.1f} karakter")
        print(f"  - Max    : {max(lengths)} karakter")
    print("----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # TAHAP 3: DATA PREPARATION
    # -----------------------------------------------------------------------
    print("======================================================================")
    print("   CRISP-DM STAGE 3: DATA PREPARATION")
    print("======================================================================")

    # Deduplikasi sebelum split berdasarkan string ternormalisasi
    dedup_dict: dict[str, dict[str, Any]] = {}
    for s in samples:
        norm_key = f"{s['method']}|{normalize(s.get('url', ''))}|{normalize(s.get('query', ''))}|{normalize(s.get('body', ''))}"
        if norm_key not in dedup_dict:
            dedup_dict[norm_key] = s

    deduped_samples = list(dedup_dict.values())
    print(f"Deduplikasi selesai: {total_loaded} -> {len(deduped_samples)} sampel unik (buang {total_loaded - len(deduped_samples)} duplikat).")

    # Ekstraksi Fitur
    f_names = feature_names()
    print(f"Mengekstrak {len(f_names)} fitur numerik per sampel...")

    X_list: list[list[float]] = []
    y_list: list[int] = []
    raw_list: list[dict[str, Any]] = []

    for s in deduped_samples:
        vec = extract_features(s["method"], s.get("url", ""), s.get("query", ""), s.get("body", ""))
        X_list.append(vec)
        y_list.append(int(s["label"]))
        raw_list.append(s)

    X = np.array(X_list)
    y = np.array(y_list)

    # Stratified Split 80:20 (Random State = 42)
    X_train, X_test, y_train, y_test, raw_train, raw_test = train_test_split(
        X, y, raw_list, test_size=0.20, random_state=42, stratify=y
    )

    print(f"Split Stratified 80:20:")
    print(f"  - Data Latih (Train) : {len(y_train)} sampel (Normal: {sum(y_train == 0)}, Serangan: {sum(y_train == 1)})")
    print(f"  - Data Uji (Hold-out): {len(y_test)} sampel (Normal: {sum(y_test == 0)}, Serangan: {sum(y_test == 1)})")
    print("----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # TAHAP 4: MODELING (GridSearchCV HANYA pada Data Latih)
    # -----------------------------------------------------------------------
    print("======================================================================")
    print("   CRISP-DM STAGE 4: MODELING")
    print("======================================================================")
    print("Melatih DecisionTreeClassifier (criterion='entropy') dengan GridSearchCV...")

    param_grid = {
        "max_depth": [5, 10, 15, 20, None],
        "min_samples_leaf": [1, 2, 5, 10],
    }
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    base_dt = DecisionTreeClassifier(criterion="entropy", random_state=42)
    grid_search = GridSearchCV(
        estimator=base_dt,
        param_grid=param_grid,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
    )
    grid_search.fit(X_train, y_train)

    best_model: DecisionTreeClassifier = grid_search.best_estimator_
    print(f"Best Parameters (5-Fold CV F1={grid_search.best_score_:.4f}):")
    for param, val in grid_search.best_params_.items():
        print(f"  - {param}: {val}")
    print("----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # TAHAP 5: EVALUATION PADA HOLD-OUT TEST SET
    # -----------------------------------------------------------------------
    print("======================================================================")
    print("   CRISP-DM STAGE 5: EVALUATION (HOLD-OUT TEST SET)")
    print("======================================================================")

    # 1. Evaluasi Model Decision Tree
    y_pred = best_model.predict(X_test)
    dt_acc = accuracy_score(y_test, y_pred)
    dt_prec = precision_score(y_test, y_pred, zero_division=0)
    dt_rec = recall_score(y_test, y_pred, zero_division=0)
    dt_f1 = f1_score(y_test, y_pred, zero_division=0)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    dt_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # 2. Evaluasi Baseline Rule-Based
    y_baseline_pred = [
        is_attack_baseline(s["method"], s.get("url", ""), s.get("query", ""), s.get("body", ""))
        for s in raw_test
    ]
    b_acc = accuracy_score(y_test, y_baseline_pred)
    b_prec = precision_score(y_test, y_baseline_pred, zero_division=0)
    b_rec = recall_score(y_test, y_baseline_pred, zero_division=0)
    b_f1 = f1_score(y_test, y_baseline_pred, zero_division=0)
    b_cm = confusion_matrix(y_test, y_baseline_pred)
    b_tn, b_fp, b_fn, b_tp = b_cm.ravel()
    b_fpr = float(b_fp / (b_fp + b_tn)) if (b_fp + b_tn) > 0 else 0.0

    # Tabel Perbandingan
    comparison_df = pd.DataFrame([
        {
            "Model": "Baseline (Keyword/Rule)",
            "Akurasi": f"{b_acc * 100:.2f}%",
            "Presisi": f"{b_prec * 100:.2f}%",
            "Recall": f"{b_rec * 100:.2f}%",
            "F1-Score": f"{b_f1 * 100:.2f}%",
            "FPR": f"{b_fpr * 100:.2f}%",
            "TP": b_tp, "FP": b_fp, "TN": b_tn, "FN": b_fn,
        },
        {
            "Model": "Decision Tree (ML-WAF)",
            "Akurasi": f"{dt_acc * 100:.2f}%",
            "Presisi": f"{dt_prec * 100:.2f}%",
            "Recall": f"{dt_rec * 100:.2f}%",
            "F1-Score": f"{dt_f1 * 100:.2f}%",
            "FPR": f"{dt_fpr * 100:.2f}%",
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        },
    ])
    print(comparison_df.to_string(index=False))

    # Target Akurasi >= 90%
    target_passed = dt_acc >= 0.90
    print("\n----------------------------------------------------------------------")
    if target_passed:
        print(f"STATUS TARGET AKURASI (>= 90%): [PASS] ({dt_acc * 100:.2f}%)")
    else:
        print(f"STATUS TARGET AKURASI (>= 90%): [FAIL] ({dt_acc * 100:.2f}%)")
    print("----------------------------------------------------------------------")

    # Top-10 Feature Importance
    importances = best_model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("\nTop-10 Feature Importance:")
    top_features = []
    for rank, idx in enumerate(sorted_idx[:10], 1):
        feat_name = f_names[idx]
        score = importances[idx]
        top_features.append({"rank": rank, "feature": feat_name, "importance": round(float(score), 4)})
        print(f"  {rank:2d}. {feat_name:<28} : {score:.4f}")
    print("----------------------------------------------------------------------\n")

    # -----------------------------------------------------------------------
    # TAHAP 6: DEPLOYMENT & ARTIFACT GENERATION
    # -----------------------------------------------------------------------
    print("======================================================================")
    print("   CRISP-DM STAGE 6: DEPLOYMENT")
    print("======================================================================")

    # 1. Simpan Bundle Model Joblib
    model_bundle = {
        "model": best_model,
        "feature_names": f_names,
        "sklearn_version": sklearn.__version__,
        "best_params": grid_search.best_params_,
        "is_synthetic": is_synthetic,
        "metrics": {
            "accuracy": round(float(dt_acc), 4),
            "precision": round(float(dt_prec), 4),
            "recall": round(float(dt_rec), 4),
            "f1": round(float(dt_f1), 4),
            "fpr": round(float(dt_fpr), 4),
        },
    }
    joblib.dump(model_bundle, model_path)
    print(f"Bundle Model tersimpan di : {model_path}")

    # 2. Simpan Gambar Confusion Matrix PNG
    cm_png_path = res_path / "mlwaf_confusion_matrix.png"
    _save_confusion_matrix_plot(cm, cm_png_path)

    # 3. Simpan Ringkasan Report JSON & CSV
    report_json = {
        "timestamp": pd.Timestamp.now().isoformat(),
        "is_synthetic": is_synthetic,
        "total_samples": total_loaded,
        "deduped_samples": len(deduped_samples),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "best_params": grid_search.best_params_,
        "decision_tree": {
            "accuracy": round(float(dt_acc), 4),
            "precision": round(float(dt_prec), 4),
            "recall": round(float(dt_rec), 4),
            "f1": round(float(dt_f1), 4),
            "fpr": round(float(dt_fpr), 4),
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        },
        "baseline": {
            "accuracy": round(float(b_acc), 4),
            "precision": round(float(b_prec), 4),
            "recall": round(float(b_rec), 4),
            "f1": round(float(b_f1), 4),
            "fpr": round(float(b_fpr), 4),
            "tp": int(b_tp), "fp": int(b_fp), "tn": int(b_tn), "fn": int(b_fn),
        },
        "target_accuracy_passed": target_passed,
        "top_features": top_features,
    }

    report_json_path = res_path / "mlwaf_report.json"
    report_json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
    print(f"Laporan JSON tersimpan di : {report_json_path}")

    metrics_csv_path = res_path / "mlwaf_metrics.csv"
    comparison_df.to_csv(metrics_csv_path, index=False)
    print(f"Tabel Metrik CSV tersimpan di: {metrics_csv_path}")

    print("======================================================================")
    print("   PELATIHAN ML-WAF CRISP-DM SELESAI")
    print("======================================================================")

    return report_json


if __name__ == "__main__":
    train_mlwaf()
