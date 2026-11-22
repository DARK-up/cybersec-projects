#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Integration Tests for DARK v4.0 API & Studio Surfaces."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent.parent
for p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if p not in sys.path:
        sys.path.insert(0, p)

import main as dark_main  # noqa: E402


def test_api_v4_routes_and_studio_endpoints():
    client = TestClient(dark_main.app)

    r_studio = client.get("/api-studio")
    assert r_studio.status_code == 200 and "DARK" in r_studio.text

    r_docs = client.get("/docs")
    assert r_docs.status_code == 200 and "/openapi.json" in r_docs.text

    r_spec = client.get("/openapi.json")
    assert r_spec.status_code == 200
    paths = r_spec.json().get("paths", {})
    assert "/api/intel/attack-matrix" in paths
    assert "/api/admin/vault/rotate" in paths
    assert "/api/admin/users/{user_id}/role" in paths

    r_atk = client.get("/api/intel/attack-matrix")
    assert r_atk.status_code == 200 and "techniques" in r_atk.json()
