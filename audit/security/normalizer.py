"""Normalizer untuk temuan keamanan dari berbagai tools (ZAP, Arachni, Nuclei).

Menstandarkan format ke Pydantic Finding:
- tool: zap | arachni | nuclei
- name: nama kerentanan
- cwe: format "CWE-<nomor>" atau None
- route: path dinormalisasi (hapus host, query string, dan ganti angka/UUID -> {id})
- method: HTTP method (GET, POST, dll.)
- param: nama parameter yang rentan atau None
- severity: Critical | High | Medium | Low | Info
- cvss: skor numerik (jika tidak ada dari tool, gunakan estimasi kasar berdasar severity)
- evidence: bukti payload / respons
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from audit.schemas import Finding, Severity

# ---------------------------------------------------------------------------
# Estimasi CVSS kasar bila tidak disediakan tool
# ---------------------------------------------------------------------------
_CVSS_ESTIMATES = {
    Severity.critical: 9.5,
    Severity.high: 7.5,
    Severity.medium: 5.5,
    Severity.low: 2.5,
    Severity.info: 0.0,
}


def estimate_cvss(severity: Severity) -> float:
    """Estimasi kasar CVSS v3 berdasarkan severity."""
    return _CVSS_ESTIMATES.get(severity, 0.0)


# ---------------------------------------------------------------------------
# Route normalizer
# ---------------------------------------------------------------------------
_UUID_REGEX = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)"
)
_NUMERIC_SEGMENT_REGEX = re.compile(r"/\d+(?=/|$)")


def normalize_route(url_or_path: str) -> str:
    """Normalisasi URL atau path API agar seragam untuk deduplikasi:
    1. Hapus scheme, host, port
    2. Hapus query string & fragment
    3. Ganti segmen UUID atau angka murni dengan {id}
    4. Pastikan diawali dengan '/' dan tidak diakhiri '/' (kecuali root '/')
    """
    if not url_or_path:
        return "/"

    # Hapus query string / fragment
    raw = url_or_path.split("?")[0].split("#")[0].strip()

    # Parse path jika format URL lengkap
    if "://" in raw:
        parsed = urlparse(raw)
        path = parsed.path
    else:
        path = raw

    if not path:
        return "/"

    # Ganti UUID dengan {id}
    path = _UUID_REGEX.sub("/{id}", path)
    # Ganti segment angka dengan {id}
    path = _NUMERIC_SEGMENT_REGEX.sub("/{id}", path)

    # Pastikan awalan '/'
    if not path.startswith("/"):
        path = "/" + path

    # Rapikan trailing slash
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    return path


def normalize_cwe(cwe_val: Any) -> str | None:
    """Format string CWE menjadi 'CWE-<nomor>'."""
    if not cwe_val:
        return None

    if isinstance(cwe_val, list):
        if not cwe_val:
            return None
        cwe_val = cwe_val[0]

    val_str = str(cwe_val).strip()
    if not val_str or val_str in ("0", "-1", "null", "None"):
        return None

    # Jika sudah berawalan CWE-
    match = re.search(r"(\d+)", val_str)
    if match:
        num = int(match.group(1))
        if num > 0:
            return f"CWE-{num}"
    return None


# ---------------------------------------------------------------------------
# ZAP Normalizer
# ---------------------------------------------------------------------------
def normalize_zap_severity(risk_code: Any, risk_name: str | None = None, cvss: float | None = None) -> Severity:
    """Petakan ZAP riskcode / risk string ke Severity.
    ZAP: 3->High, 2->Medium, 1->Low, 0->Informational
    Critical hanya jika CVSS >= 9.0 atau label eksplisit Critical.
    """
    if cvss is not None and cvss >= 9.0:
        return Severity.critical

    r_str = str(risk_name or "").lower()
    if "critical" in r_str:
        return Severity.critical

    code_str = str(risk_code).strip()
    if code_str == "3" or "high" in r_str:
        return Severity.high
    elif code_str == "2" or "medium" in r_str:
        return Severity.medium
    elif code_str == "1" or "low" in r_str:
        return Severity.low
    elif code_str == "0" or "info" in r_str:
        return Severity.info

    return Severity.info


def normalize_zap(raw: list[dict[str, Any]] | dict[str, Any]) -> list[Finding]:
    """Konversi raw output alerts dari ZAP (core/view/alerts) ke list Finding."""
    findings: list[Finding] = []

    # Format ZAP bisa berupa {"alerts": [...]} atau list langsung
    alerts: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        alerts = raw.get("alerts", [])
    elif isinstance(raw, list):
        alerts = raw

    for item in alerts:
        name = item.get("alert") or item.get("name") or "Unknown ZAP Alert"
        url = item.get("url", "/")
        route = normalize_route(url)
        method = (item.get("method") or "GET").upper()
        param = item.get("param") or None
        cwe = normalize_cwe(item.get("cweid"))

        # CVSS dari ZAP alert jika ada
        cvss: float | None = None
        if "cvss" in item and item["cvss"]:
            try:
                cvss = float(item["cvss"])
            except (ValueError, TypeError):
                pass

        risk_code = item.get("riskcode") or item.get("riskCode")
        risk_name = item.get("risk")
        sev = normalize_zap_severity(risk_code, risk_name, cvss)

        if cvss is None:
            cvss = estimate_cvss(sev)

        evidence = item.get("evidence") or item.get("attack") or item.get("description")

        findings.append(Finding(
            tool="zap",
            name=name,
            cwe=cwe,
            route=route,
            method=method,
            param=param,
            severity=sev,
            cvss=cvss,
            evidence=evidence[:300] if evidence else None,
        ))

    return findings


# ---------------------------------------------------------------------------
# Arachni Normalizer
# ---------------------------------------------------------------------------
def normalize_arachni_severity(sev_str: str | None) -> Severity:
    s = (sev_str or "").lower().strip()
    if s == "critical":
        return Severity.critical
    elif s == "high":
        return Severity.high
    elif s == "medium":
        return Severity.medium
    elif s == "low":
        return Severity.low
    return Severity.info


def normalize_arachni(raw: list[dict[str, Any]] | dict[str, Any]) -> list[Finding]:
    """Konversi output JSON report dari Arachni (issues) ke list Finding."""
    findings: list[Finding] = []

    issues: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        issues = raw.get("issues", [])
    elif isinstance(raw, list):
        issues = raw

    for item in issues:
        name = item.get("name") or "Unknown Arachni Issue"
        cwe = normalize_cwe(item.get("cwe"))

        vector = item.get("vector", {}) if isinstance(item.get("vector"), dict) else {}
        page = item.get("page", {}) if isinstance(item.get("page"), dict) else {}

        url = vector.get("action") or vector.get("url") or page.get("url") or "/"
        route = normalize_route(url)

        method = (vector.get("method") or page.get("method") or "GET").upper()
        param = vector.get("name") or None

        sev = normalize_arachni_severity(item.get("severity"))

        cvss: float | None = None
        for cvss_key in ("cvssv3", "cvssv2", "cvss"):
            if cvss_key in item and item[cvss_key]:
                try:
                    cvss = float(item[cvss_key])
                    break
                except (ValueError, TypeError):
                    pass

        if cvss is None:
            cvss = estimate_cvss(sev)

        proof = item.get("proof") or item.get("signature") or item.get("description")

        findings.append(Finding(
            tool="arachni",
            name=name,
            cwe=cwe,
            route=route,
            method=method,
            param=param,
            severity=sev,
            cvss=cvss,
            evidence=str(proof)[:300] if proof else None,
        ))

    return findings


# ---------------------------------------------------------------------------
# Nuclei Normalizer
# ---------------------------------------------------------------------------
def normalize_nuclei_severity(sev_str: str | None) -> Severity:
    s = (sev_str or "").lower().strip()
    if s == "critical":
        return Severity.critical
    elif s == "high":
        return Severity.high
    elif s == "medium":
        return Severity.medium
    elif s == "low":
        return Severity.low
    return Severity.info


def normalize_nuclei(raw: list[dict[str, Any]] | dict[str, Any]) -> list[Finding]:
    """Konversi output JSON/JSONL dari Nuclei ke list Finding."""
    findings: list[Finding] = []

    items: list[dict[str, Any]] = []
    if isinstance(raw, dict):
        if "findings" in raw and isinstance(raw["findings"], list):
            items = raw["findings"]
        else:
            items = [raw]
    elif isinstance(raw, list):
        items = raw

    for item in items:
        info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        name = info.get("name") or item.get("template-id") or "Unknown Nuclei Issue"

        # Classification (CWE & CVSS)
        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cwe_raw = classification.get("cwe-id")
        cwe = normalize_cwe(cwe_raw)

        cvss: float | None = None
        if "cvss-score" in classification and classification["cvss-score"]:
            try:
                cvss = float(classification["cvss-score"])
            except (ValueError, TypeError):
                pass

        sev = normalize_nuclei_severity(info.get("severity"))
        if cvss is None:
            cvss = estimate_cvss(sev)

        matched_url = item.get("matched-at") or item.get("host") or "/"
        route = normalize_route(matched_url)

        # Method dari curl-command atau request
        method = "GET"
        curl = item.get("curl-command", "")
        if "-X POST" in curl:
            method = "POST"
        elif "-X PUT" in curl:
            method = "PUT"
        elif "-X DELETE" in curl:
            method = "DELETE"
        elif "method" in item:
            method = str(item["method"]).upper()

        param: str | None = None
        extracted = item.get("extracted-results")
        if isinstance(extracted, list) and extracted:
            param = str(extracted[0])

        evidence = item.get("matcher-name") or str(extracted) if extracted else None

        findings.append(Finding(
            tool="nuclei",
            name=name,
            cwe=cwe,
            route=route,
            method=method,
            param=param,
            severity=sev,
            cvss=cvss,
            evidence=evidence[:300] if evidence else None,
        ))

    return findings
