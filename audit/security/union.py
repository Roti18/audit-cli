"""Union List Aggregator untuk temuan keamanan (ZAP + Scanner kedua).

Menghasilkan himpunan gabungan (Union List) yang terdeduplikasi:
- Kunci deduplikasi: (cwe, route, param, method)
- Resolusi duplikat: Memilih severity tertinggi dan menandai tool = 'zap+<scanner2>'
- Menghitung irisan (intersection) untuk analisis statistik dan metrik
- Urutan deterministik stabil (berdasarkan tingkat keparahan, route, CWE)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from audit.schemas import Finding, Severity, save_json
from audit.security.normalizer import normalize_cwe, normalize_route

_SEVERITY_RANKS = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}


def _make_dedup_key(finding: Finding) -> tuple[str, str, str, str]:
    """Membuat kunci unik deduplikasi untuk temuan keamanan."""
    cwe = normalize_cwe(finding.cwe) or "NO-CWE"
    route = normalize_route(finding.route)
    param = (finding.param or "").strip().lower()
    method = (finding.method or "GET").strip().upper()
    return (cwe, route, param, method)


def union_findings(
    zap_findings: list[Finding],
    scanner2_findings: list[Finding],
    scanner2_name: str = "nuclei",
) -> tuple[list[Finding], list[Finding]]:
    """Menggabungkan temuan ZAP dan Scanner kedua menjadi Union List & Intersection List.

    Args:
        zap_findings: Daftar temuan dari OWASP ZAP.
        scanner2_findings: Daftar temuan dari scanner kedua (Arachni/Nuclei).
        scanner2_name: Nama scanner kedua untuk label tool gabungan.

    Returns:
        tuple (union_list, intersection_list) yang terurut deterministik.
    """
    zap_dict: dict[tuple[str, str, str, str], Finding] = {}
    s2_dict: dict[tuple[str, str, str, str], Finding] = {}

    for f in zap_findings:
        k = _make_dedup_key(f)
        if k not in zap_dict or _SEVERITY_RANKS[f.severity] > _SEVERITY_RANKS[zap_dict[k].severity]:
            zap_dict[k] = f

    for f in scanner2_findings:
        k = _make_dedup_key(f)
        if k not in s2_dict or _SEVERITY_RANKS[f.severity] > _SEVERITY_RANKS[s2_dict[k].severity]:
            s2_dict[k] = f

    union_map: dict[tuple[str, str, str, str], Finding] = {}
    intersection_list: list[Finding] = []

    # 1. Masukkan semua temuan ZAP
    for k, f in zap_dict.items():
        union_map[k] = f.model_copy()

    # 2. Gabungkan temuan Scanner2
    for k, f2 in s2_dict.items():
        if k in union_map:
            # Temuan duplikat terdeteksi oleh kedua tool (Intersection)
            f_existing = union_map[k]
            higher_sev = (
                f2.severity
                if _SEVERITY_RANKS[f2.severity] > _SEVERITY_RANKS[f_existing.severity]
                else f_existing.severity
            )
            cvss = max(f_existing.cvss or 0.0, f2.cvss or 0.0) or None

            merged = Finding(
                tool=f"zap+{scanner2_name}",
                name=f_existing.name if len(f_existing.name) >= len(f2.name) else f2.name,
                cwe=f_existing.cwe or f2.cwe,
                route=f_existing.route,
                method=f_existing.method,
                param=f_existing.param or f2.param,
                severity=higher_sev,
                cvss=cvss,
                evidence=f_existing.evidence or f2.evidence,
            )
            union_map[k] = merged
            intersection_list.append(merged)
        else:
            union_map[k] = f2.model_copy()

    # 3. Urutkan secara deterministik
    def _sort_key(f: Finding) -> tuple[int, str, str, str]:
        return (
            -_SEVERITY_RANKS.get(f.severity, 0),
            f.route,
            f.cwe or "",
            f.name,
        )

    union_list = sorted(union_map.values(), key=_sort_key)
    intersection_list = sorted(intersection_list, key=_sort_key)

    return union_list, intersection_list


def save_union(
    union_list: list[Finding],
    output_path: str | Path,
) -> Path:
    """Menyimpan Union List ke berkas JSON."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = [f.model_dump(by_alias=True) for f in union_list]
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return p
