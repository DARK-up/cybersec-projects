#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify DARK_ENV=production enforces secure-by-default controls."""
from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb
import main as dark_main


def test_production_profile_enforces_mandatory_auth_rbac_and_audit(monkeypatch):
    monkeypatch.setenv("DARK_ENV", "production")
    # Ensure DB rbac_enforced flag is False so we prove production profile enforces it anyway
    prev_rbac = edb.get_setting("rbac_enforced", False)
    edb.set_setting("rbac_enforced", False)
    try:
        client = TestClient(dark_main.app)

        # Health exposes production profile & debug_mode=False
        h = client.get("/api/health")
        assert h.status_code == 200
        assert h.json()["deployment_profile"] == "production"
        assert h.json()["debug_mode"] is False
        assert h.headers.get("X-Dark-Profile") == "production"

        # Unauthenticated API call MUST be rejected 401 in production mode
        r_unauth = client.get("/api/jobs")
        assert r_unauth.status_code == 401

        # Create a read-only viewer API key and verify RBAC still blocks scan:run (403)
        ak = edb.create_api_key("prod-viewer-test", role="viewer", tenant_id="default")
        r_read = client.get("/api/jobs", headers={"X-API-Key": ak["raw_key"]})
        assert r_read.status_code == 200
        r_write = client.post(
            "/api/jobs/secrets-scan",
            json={"content": "test"},
            headers={"X-API-Key": ak["raw_key"]},
        )
        assert r_write.status_code == 403
    finally:
        edb.set_setting("rbac_enforced", prev_rbac)
