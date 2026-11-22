"""Tests for security/normalizer.py – Normalisasi temuan ZAP, Arachni, dan Nuclei."""

from __future__ import annotations

import pytest

from audit.schemas import Finding, Severity
from audit.security.normalizer import (
    estimate_cvss,
    normalize_arachni,
    normalize_cwe,
    normalize_nuclei,
    normalize_route,
    normalize_zap,
)


# ---------------------------------------------------------------------------
# Test Route Normalization
# ---------------------------------------------------------------------------
class TestRouteNormalization:
    def test_strip_host_and_protocol(self):
        assert normalize_route("http://localhost:3000/api/Products") == "/api/Products"
        assert normalize_route("https://example.com:8443/api/v1/users") == "/api/v1/users"

    def test_strip_query_string(self):
        assert normalize_route("http://localhost:3000/rest/products/search?q=apple&category=fruit") == "/rest/products/search"
        assert normalize_route("/search?query=test#section") == "/search"

    def test_numeric_id_replaced(self):
        assert normalize_route("http://localhost:3000/api/Products/42") == "/api/Products/{id}"
        assert normalize_route("/rest/basket/12345") == "/rest/basket/{id}"
        assert normalize_route("/users/1/posts/99/comments") == "/users/{id}/posts/{id}/comments"

    def test_uuid_replaced(self):
        assert normalize_route("/api/orders/550e8400-e29b-41d4-a716-446655440000") == "/api/orders/{id}"
        assert normalize_route("http://localhost:3000/api/orders/550E8400-E29B-41D4-A716-446655440000/items") == "/api/orders/{id}/items"

    def test_already_templated(self):
        assert normalize_route("/api/Products/{id}") == "/api/Products/{id}"

    def test_empty_and_root(self):
        assert normalize_route("") == "/"
        assert normalize_route("/") == "/"
        assert normalize_route("http://localhost:3000") == "/"


# ---------------------------------------------------------------------------
# Test CWE Normalization
# ---------------------------------------------------------------------------
class TestCWENormalization:
    def test_integer_cwe(self):
        assert normalize_cwe(89) == "CWE-89"
        assert normalize_cwe(79) == "CWE-79"

    def test_string_cwe(self):
        assert normalize_cwe("89") == "CWE-89"
        assert normalize_cwe("CWE-89") == "CWE-89"
        assert normalize_cwe("cwe-20") == "CWE-20"

    def test_list_cwe(self):
        assert normalize_cwe(["CWE-89", "CWE-20"]) == "CWE-89"
        assert normalize_cwe([79]) == "CWE-79"

    def test_invalid_or_empty_cwe(self):
        assert normalize_cwe(None) is None
        assert normalize_cwe(0) is None
        assert normalize_cwe("0") is None
        assert normalize_cwe("-1") is None
        assert normalize_cwe([]) is None


# ---------------------------------------------------------------------------
# Test CVSS Estimation
# ---------------------------------------------------------------------------
class TestCVSSEstimation:
    def test_estimates(self):
        assert estimate_cvss(Severity.critical) >= 9.0
        assert 7.0 <= estimate_cvss(Severity.high) < 9.0
        assert 4.0 <= estimate_cvss(Severity.medium) < 7.0
        assert 0.1 <= estimate_cvss(Severity.low) < 4.0
        assert estimate_cvss(Severity.info) == 0.0


# ---------------------------------------------------------------------------
# Test ZAP Normalization
# ---------------------------------------------------------------------------
class TestZAPNormalization:
    @pytest.fixture
    def zap_raw_sample(self):
        return {
            "alerts": [
                {
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "risk": "High",
                    "cweid": "89",
                    "url": "http://localhost:3000/rest/products/search?q=test",
                    "method": "GET",
                    "param": "q",
                    "evidence": "SQL syntax error",
                    "attack": "' OR '1'='1",
                },
                {
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskcode": "2",
                    "risk": "Medium",
                    "cweid": "79",
                    "url": "http://localhost:3000/api/Products/15",
                    "method": "GET",
                    "param": "id",
                    "evidence": "<script>alert(1)</script>",
                },
                {
                    "alert": "Remote Code Execution",
                    "riskcode": "3",
                    "risk": "High",
                    "cweid": "78",
                    "url": "http://localhost:3000/api/system/exec",
                    "method": "POST",
                    "cvss": 9.8,
                    "evidence": "root:x:0:0",
                },
                {
                    "alert": "Information Disclosure - Comments",
                    "riskcode": "0",
                    "risk": "Informational",
                    "cweid": "200",
                    "url": "http://localhost:3000/api/info",
                    "method": "GET",
                },
            ]
        }

    def test_normalize_zap_alerts(self, zap_raw_sample):
        findings = normalize_zap(zap_raw_sample)
        assert len(findings) == 4

        # 1. SQLi
        sqli = findings[0]
        assert sqli.tool == "zap"
        assert sqli.name == "SQL Injection"
        assert sqli.cwe == "CWE-89"
        assert sqli.route == "/rest/products/search"
        assert sqli.method == "GET"
        assert sqli.param == "q"
        assert sqli.severity == Severity.high
        assert sqli.evidence == "SQL syntax error"

        # 2. XSS with numeric id in route
        xss = findings[1]
        assert xss.route == "/api/Products/{id}"
        assert xss.severity == Severity.medium
        assert xss.cwe == "CWE-79"

        # 3. RCE with CVSS 9.8 -> Escalates to Critical
        rce = findings[2]
        assert rce.severity == Severity.critical
        assert rce.cvss == 9.8

        # 4. Info
        info = findings[3]
        assert info.severity == Severity.info

    def test_normalize_empty_zap(self):
        assert normalize_zap({"alerts": []}) == []
        assert normalize_zap([]) == []
        assert normalize_zap({"error": "Failed"}) == []


# ---------------------------------------------------------------------------
# Test Arachni Normalization
# ---------------------------------------------------------------------------
class TestArachniNormalization:
    @pytest.fixture
    def arachni_raw_sample(self):
        return {
            "issues": [
                {
                    "name": "SQL Injection in path",
                    "severity": "high",
                    "cwe": "89",
                    "cvssv3": 8.5,
                    "vector": {
                        "action": "http://localhost:3000/api/Products/100?sort=name",
                        "method": "get",
                        "name": "id",
                    },
                    "proof": "syntax error near SELECT",
                },
                {
                    "name": "Cross-Site Scripting (XSS)",
                    "severity": "medium",
                    "cwe": 79,
                    "page": {
                        "url": "http://localhost:3000/rest/track-order/TRACK123",
                        "method": "get",
                    },
                },
            ]
        }

    def test_normalize_arachni_issues(self, arachni_raw_sample):
        findings = normalize_arachni(arachni_raw_sample)
        assert len(findings) == 2

        f1 = findings[0]
        assert f1.tool == "arachni"
        assert f1.name == "SQL Injection in path"
        assert f1.cwe == "CWE-89"
        assert f1.route == "/api/Products/{id}"
        assert f1.method == "GET"
        assert f1.param == "id"
        assert f1.severity == Severity.high
        assert f1.cvss == 8.5

        f2 = findings[1]
        assert f2.route == "/rest/track-order/TRACK123"
        assert f2.severity == Severity.medium
        assert f2.cwe == "CWE-79"


# ---------------------------------------------------------------------------
# Test Nuclei Normalization
# ---------------------------------------------------------------------------
class TestNucleiNormalization:
    @pytest.fixture
    def nuclei_raw_sample(self):
        return {
            "findings": [
                {
                    "template-id": "sqli-error-based",
                    "info": {
                        "name": "Generic SQL Injection Detection",
                        "severity": "high",
                        "classification": {
                            "cwe-id": ["cwe-89"],
                            "cvss-score": 8.1,
                        },
                    },
                    "matched-at": "http://localhost:3000/rest/products/search?q=123",
                    "curl-command": "curl -X GET 'http://localhost:3000/rest/products/search?q=123'",
                    "extracted-results": ["q"],
                },
                {
                    "template-id": "stored-xss",
                    "info": {
                        "name": "Stored XSS in Feedback",
                        "severity": "critical",
                        "classification": {
                            "cwe-id": "CWE-79",
                            "cvss-score": 9.3,
                        },
                    },
                    "matched-at": "http://localhost:3000/api/Feedbacks/99",
                    "curl-command": "curl -X POST 'http://localhost:3000/api/Feedbacks/99'",
                },
            ]
        }

    def test_normalize_nuclei_findings(self, nuclei_raw_sample):
        findings = normalize_nuclei(nuclei_raw_sample)
        assert len(findings) == 2

        f1 = findings[0]
        assert f1.tool == "nuclei"
        assert f1.name == "Generic SQL Injection Detection"
        assert f1.cwe == "CWE-89"
        assert f1.route == "/rest/products/search"
        assert f1.severity == Severity.high
        assert f1.param == "q"

        f2 = findings[1]
        assert f2.route == "/api/Feedbacks/{id}"
        assert f2.method == "POST"
        assert f2.severity == Severity.critical
        assert f2.cvss == 9.3
