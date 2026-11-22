"""Tests for audit/mlwaf/features.py and train.py – Ekstraksi fitur, normalisasi, dan pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from sklearn.tree import DecisionTreeClassifier

from audit.mlwaf.features import (
    ATTACK_KEYWORDS,
    SPECIAL_CHARS,
    extract_features,
    feature_names,
    generate_synthetic_csic_dataset,
    is_attack_baseline,
    normalize,
    parse_raw_requests,
)
from audit.mlwaf.train import evaluate_on_requests


# ---------------------------------------------------------------------------
# Test Normalisasi
# ---------------------------------------------------------------------------
class TestNormalizer:
    def test_single_url_decode(self):
        assert normalize("user%27+or+1%3D1--") == "user' or 1=1--"

    def test_double_url_decode(self):
        # %2527 -> %27 -> '
        assert normalize("admin%2527+or+%25271") == "admin' or '1"

    def test_triple_url_decode(self):
        # %25253c -> %253c -> %3c -> <
        assert normalize("%25253cscript%25253e") == "<script>"

    def test_lowercase(self):
        assert normalize("SELECT * FROM USERS") == "select * from users"
        assert normalize("<SCRIPT>Alert(1)</SCRIPT>") == "<script>alert(1)</script>"

    def test_empty_or_none(self):
        assert normalize("") == ""
        assert normalize(None) == ""


# ---------------------------------------------------------------------------
# Test Ekstraksi Fitur
# ---------------------------------------------------------------------------
class TestFeatureExtraction:
    def test_feature_vector_length_and_type(self):
        names = feature_names()
        vec = extract_features("GET", "/api/Products", "category=1", "")
        assert len(vec) == len(names)
        assert all(isinstance(v, (int, float)) for v in vec)

    def test_sqli_features(self):
        names = feature_names()
        normal_vec = extract_features("GET", "/rest/products/search", "q=apple", "")
        sqli_vec = extract_features("GET", "/rest/products/search", "q=apple%27+union+select+1%2C2%2C3--", "")

        idx_union = names.index("kw_union")
        idx_select = names.index("kw_select")
        idx_quote = names.index("char_single_quote")
        idx_dash_dash = names.index("char_dash_dash")

        assert normal_vec[idx_union] == 0.0
        assert normal_vec[idx_select] == 0.0
        assert normal_vec[idx_quote] == 0.0

        assert sqli_vec[idx_union] >= 1.0
        assert sqli_vec[idx_select] >= 1.0
        assert sqli_vec[idx_quote] >= 1.0
        assert sqli_vec[idx_dash_dash] >= 1.0

    def test_xss_features(self):
        names = feature_names()
        xss_vec = extract_features("POST", "/api/Feedbacks", "", "comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")

        idx_script = names.index("kw_script")
        idx_alert = names.index("kw_alert")
        idx_lt = names.index("char_lt")
        idx_gt = names.index("char_gt")

        assert xss_vec[idx_script] >= 1.0
        assert xss_vec[idx_alert] >= 1.0
        assert xss_vec[idx_lt] >= 1.0
        assert xss_vec[idx_gt] >= 1.0

    def test_method_one_hot(self):
        names = feature_names()
        idx_is_post = names.index("is_post")
        idx_is_get = names.index("is_get")

        post_vec = extract_features("POST", "/api/login", "", "user=a&pass=b")
        assert post_vec[idx_is_post] == 1.0
        assert post_vec[idx_is_get] == 0.0

        get_vec = extract_features("GET", "/api/login", "user=a", "")
        assert get_vec[idx_is_post] == 0.0
        assert get_vec[idx_is_get] == 1.0


# ---------------------------------------------------------------------------
# Test Raw HTTP Parser
# ---------------------------------------------------------------------------
class TestRawHttpParser:
    def test_parse_raw_text(self, tmp_path):
        raw_http = """GET http://localhost:8080/tienda1/index.jsp?cat=1 HTTP/1.1
User-Agent: Mozilla/5.0
Host: localhost:8080

POST http://localhost:8080/tienda1/login.jsp HTTP/1.1
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 21

user=admin&pass=secret
"""
        sample_file = tmp_path / "traffic.txt"
        sample_file.write_text(raw_http, encoding="utf-8")

        parsed = parse_raw_requests(sample_file)
        assert len(parsed) == 2

        req1 = parsed[0]
        assert req1["method"] == "GET"
        assert req1["url"] == "/tienda1/index.jsp"
        assert req1["query"] == "cat=1"

        req2 = parsed[1]
        assert req2["method"] == "POST"
        assert req2["url"] == "/tienda1/login.jsp"
        assert req2["body"] == "user=admin&pass=secret"


# ---------------------------------------------------------------------------
# Test Baseline & Evaluation Helper
# ---------------------------------------------------------------------------
class TestBaselineAndEvaluation:
    def test_baseline_detector(self):
        assert is_attack_baseline("GET", "/search", "q=normal+query", "") == 0
        assert is_attack_baseline("GET", "/search", "q=1%27+or+1%3D1--", "") == 1
        assert is_attack_baseline("POST", "/comment", "", "text=<script>alert(1)</script>") == 1
        assert is_attack_baseline("GET", "/download", "file=../../etc/passwd", "") == 1

    def test_evaluate_on_requests_with_mock_model(self):
        # Buat model DecisionTree sederhana
        X = [
            extract_features("GET", "/normal", "", ""),
            extract_features("GET", "/sqli", "q=' union select", ""),
        ]
        y = [0, 1]
        dt = DecisionTreeClassifier(random_state=42)
        dt.fit(X, y)

        test_requests = [
            {"method": "GET", "url": "/normal", "query": "", "body": ""},
            {"method": "GET", "url": "/sqli", "query": "q=' union select", "body": ""},
        ]

        eval_res = evaluate_on_requests(dt, test_requests)
        assert eval_res["total"] == 2
        assert eval_res["blocked"] == 1
        assert eval_res["allowed"] == 1
        assert eval_res["detection_rate"] == 0.5


# ---------------------------------------------------------------------------
# Test Synthetic CSIC Dataset Generator
# ---------------------------------------------------------------------------
class TestSyntheticGenerator:
    def test_generate_synthetic_files(self, tmp_path):
        paths = generate_synthetic_csic_dataset(tmp_path)
        for key, p in paths.items():
            assert p.exists()
            assert p.stat().st_size > 0

        # Verifikasi parser bisa membaca file sintetis
        train_samples = parse_raw_requests(paths["normal_train"])
        assert len(train_samples) > 100
