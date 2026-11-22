"""Clean API Mock Service untuk Verifikasi Jalur Sukses (PASSED / CONDITIONAL PASS).

API aman yang memenuhi praktik terbaik produksi:
- 7 endpoint terstruktur dengan validasi input ketat (Pydantic / data type checks).
- Mengembalikan HTTP 400 Bad Request untuk input yang tidak valid (bukan 500 atau SQL error).
- Mengembalikan HTTP 401 Unauthorized jika header Authorization tidak ada pada rute terproteksi.
- Tanpa kerentanan injeksi sengaja (parameterized logic, sanitized output).
- Respons super cepat (< 10 ms) untuk menjamin Platency = 100 dan Pperf optimal.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from flask import Flask, jsonify, request

app = Flask("clean-api")
logging.basicConfig(level=logging.INFO)

# In-memory clean dataset
ITEMS_DB = [
    {"id": 1, "name": "Buku Panduan Metode Penelitian", "price": 45000.0, "stock": 10},
    {"id": 2, "name": "Laptop Stand Ergonomis", "price": 125000.0, "stock": 5},
    {"id": 3, "name": "Mechanical Keyboard RGB", "price": 350000.0, "stock": 8},
    {"id": 4, "name": "USB-C Hub Multiport 7-in-1", "price": 199000.0, "stock": 12},
    {"id": 5, "name": "Monitor Arm Gas Spring", "price": 280000.0, "stock": 4},
]


@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    """Healthcheck endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "clean-api",
        "version": "1.0.0",
        "production_ready": True,
    }), 200


@app.route("/api/v1/items", methods=["GET"])
def list_items():
    """Daftar seluruh item yang tersedia."""
    return jsonify({
        "total": len(ITEMS_DB),
        "data": ITEMS_DB,
    }), 200


@app.route("/api/v1/items/<item_id>", methods=["GET"])
def get_item(item_id: str):
    """Mendapatkan detail item berdasarkan ID dengan validasi ketat."""
    if not item_id.isdigit():
        return jsonify({"error": "Bad Request", "message": "ID item harus berupa bilangan bulat positif."}), 400

    i_id = int(item_id)
    item = next((it for it in ITEMS_DB if it["id"] == i_id), None)
    if not item:
        return jsonify({"error": "Not Found", "message": f"Item dengan ID {i_id} tidak ditemukan."}), 404

    return jsonify(item), 200


@app.route("/api/v1/items", methods=["POST"])
def create_item():
    """Membuat item baru dengan validasi schema ketat."""
    if not request.is_json:
        return jsonify({"error": "Bad Request", "message": "Content-Type harus application/json."}), 400

    data = request.get_json() or {}
    name = data.get("name")
    price = data.get("price")
    stock = data.get("stock", 1)

    if not name or not isinstance(name, str) or len(name.strip()) == 0:
        return jsonify({"error": "Bad Request", "message": "Field 'name' wajib diisi berupa string non-kosong."}), 400

    if not isinstance(price, (int, float)) or price <= 0:
        return jsonify({"error": "Bad Request", "message": "Field 'price' wajib berupa angka positif."}), 400

    if not isinstance(stock, int) or stock < 0:
        return jsonify({"error": "Bad Request", "message": "Field 'stock' harus berupa integer >= 0."}), 400

    new_id = max(it["id"] for it in ITEMS_DB) + 1 if ITEMS_DB else 1
    new_item = {"id": new_id, "name": name.strip(), "price": float(price), "stock": stock}
    ITEMS_DB.append(new_item)

    return jsonify(new_item), 201


@app.route("/api/v1/search", methods=["GET"])
def search_items():
    """Pencarian item yang aman dari injeksi SQL/NoSQL (Python list comprehension)."""
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify({"total": 0, "data": []}), 200

    results = [it for it in ITEMS_DB if q in it["name"].lower()]
    return jsonify({"query": q, "total": len(results), "data": results}), 200


@app.route("/api/v1/secure-data", methods=["GET"])
def secure_data():
    """Endpoint yang mensyaratkan autentikasi Bearer token."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized", "message": "Header Authorization Bearer token wajib disertakan."}), 401

    token = auth_header.split(" ", 1)[1].strip()
    if token != "valid_secret_token_123":
        return jsonify({"error": "Forbidden", "message": "Token tidak valid atau kedaluwarsa."}), 403

    return jsonify({
        "status": "authorized",
        "secret_metrics": {"kpi": 99.9, "compliance": "ISO-27001"},
    }), 200


@app.route("/api/v1/status", methods=["GET"])
def system_status():
    """Status kapasitas dan kesiapan sistem."""
    return jsonify({
        "uptime": 99.99,
        "database_connected": True,
        "load": "optimal",
    }), 200


@app.route("/openapi.json", methods=["GET"])
def openapi_spec():
    """Menyediakan OpenAPI 3.0 spec secara langsung."""
    return jsonify({
        "openapi": "3.0.3",
        "info": {
            "title": "Clean Production API",
            "version": "1.0.0",
            "description": "Mock API aman dan patuh standar produksi untuk verifikasi jalur PASSED pada audit kesiapan produksi.",
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Healthcheck",
                    "responses": {"200": {"description": "Service sehat"}},
                }
            },
            "/api/v1/items": {
                "get": {
                    "summary": "Daftar item",
                    "responses": {"200": {"description": "Daftar item"}},
                },
                "post": {
                    "summary": "Tambah item",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"type": "object", "required": ["name", "price"]}}},
                    },
                    "responses": {"201": {"description": "Item berhasil dibuat"}, "400": {"description": "Input tidak valid"}},
                },
            },
            "/api/v1/items/{id}": {
                "get": {
                    "summary": "Detail item",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Detail item"}, "400": {"description": "ID salah"}, "404": {"description": "Tidak ditemukan"}},
                }
            },
            "/api/v1/search": {
                "get": {
                    "summary": "Pencarian item",
                    "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Hasil pencarian"}},
                }
            },
            "/api/v1/secure-data": {
                "get": {
                    "summary": "Data rahasia terproteksi token",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "Data rahasia"}, "401": {"description": "Unauthorized"}},
                }
            },
            "/api/v1/status": {
                "get": {
                    "summary": "Status sistem",
                    "responses": {"200": {"description": "Status sistem"}},
                }
            },
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"}
            }
        },
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
