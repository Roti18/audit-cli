"""Unit test untuk Active Defense Verifier (mitmproxy + ML-WAF)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from audit.drivers.waf_verifier import (
    _find_mitmdump,
    _save_waf_cm_plot,
    build_realtime_test_set,
    run_waf_verifier,
)
from audit.mlwaf.mitm_addon import MLWAFAddon
from audit.schemas import Param, ParamLocation, Registry, Route


@pytest.fixture
def sample_registry() -> Registry:
    return Registry(
        target_url="http://localhost:3000",
        routes=[
            Route(
                method="GET",
                path="/api/Products/{id}",
                params=[Param(name="id", location=ParamLocation.path, required=True)],
            ),
            Route(
                method="GET",
                path="/rest/products/search",
                params=[Param(name="q", location=ParamLocation.query)],
            ),
            Route(
                method="POST",
                path="/rest/user/login",
                params=[],
            ),
        ],
    )


def test_build_realtime_test_set(sample_registry: Registry, tmp_path: Path):
    test_set = build_realtime_test_set(sample_registry, tmp_path, num_normal=10)

    assert len(test_set) >= 20
    normal_items = [t for t in test_set if t["label"] == 0]
    attack_items = [t for t in test_set if t["label"] == 1]

    assert len(normal_items) == 10
    assert len(attack_items) >= 10

    # Pastikan kategori terisi dan tidak ada data leakage ke CSIC
    for n in normal_items:
        assert n["category"] == "normal_functional"
        assert n["label"] == 0

    for a in attack_items:
        assert a["category"] in ("zap_active_scan", "synthetic_injection_test")
        assert a["label"] == 1


def test_build_realtime_test_set_with_zap_attacks(sample_registry: Registry, tmp_path: Path):
    zap_file = tmp_path / "zap_attack_requests.json"
    zap_requests = [
        {"method": "GET", "url": "http://localhost:3000/rest/products/search?q=%27+OR+1%3D1--", "body": ""},
        {"method": "POST", "url": "http://localhost:3000/rest/user/login", "body": "user=admin%27--"},
    ]
    zap_file.write_text(json.dumps(zap_requests), encoding="utf-8")

    test_set = build_realtime_test_set(sample_registry, tmp_path, num_normal=5)
    zap_items = [t for t in test_set if t.get("category") == "zap_active_scan"]
    assert len(zap_items) == 2
    assert zap_items[0]["label"] == 1


def test_save_waf_cm_plot(tmp_path: Path):
    cm = np.array([[38, 2], [1, 39]])
    out_file = tmp_path / "waf_cm.png"
    _save_waf_cm_plot(cm, out_file)
    assert out_file.exists()
    assert out_file.stat().st_size > 500


def test_run_waf_verifier_missing_mitmdump(sample_registry: Registry, tmp_path: Path):
    with patch("audit.drivers.waf_verifier._find_mitmdump", return_value=None):
        res = run_waf_verifier(sample_registry, tmp_path)
        assert res["status"] == "FAIL"
        assert res["evaluated"] is False
        assert (tmp_path / "waf.json").exists()


def test_mlwaf_mitm_addon_interception(tmp_path: Path):
    addon = MLWAFAddon()
    model_file = Path("audit/mlwaf/model.joblib")
    if not model_file.exists():
        pytest.skip("Model ML-WAF belum ada")

    addon.model_path = model_file
    addon.log_file = tmp_path / "waf_decisions.jsonl"
    addon.load(None)
    assert addon.model is not None

    # 1. Test request normal
    mock_flow_normal = MagicMock()
    mock_flow_normal.request.method = "GET"
    mock_flow_normal.request.path = "/tienda1/publico/caracteristicas.jsp"
    mock_flow_normal.request.url = "http://localhost:3000/tienda1/publico/caracteristicas.jsp?id=2"
    mock_flow_normal.request.query = {"id": "2"}
    mock_flow_normal.request.headers = {}
    mock_flow_normal.request.get_text.return_value = ""

    addon.request(mock_flow_normal)
    # Permintaan normal diteruskan dengan header X-WAF-Decision: allowed
    assert mock_flow_normal.request.headers.get("X-WAF-Decision") == "allowed"

    # 2. Test request serangan SQL injection yang jelas
    mock_flow_attack = MagicMock()
    mock_flow_attack.request.method = "POST"
    mock_flow_attack.request.path = "/rest/user/login"
    mock_flow_attack.request.url = "http://localhost:3000/rest/user/login"
    mock_flow_attack.request.query = {}
    mock_flow_attack.request.headers = {}
    mock_flow_attack.request.get_text.return_value = "email=admin%27+or+1%3D1--&password=foo"

    addon.request(mock_flow_attack)
    # Pastikan response diblokir
    assert mock_flow_attack.response is not None
    assert mock_flow_attack.response.status_code == 403
    assert mock_flow_attack.response.headers.get("X-WAF-Decision") == "blocked"
    assert addon.log_file.exists()
