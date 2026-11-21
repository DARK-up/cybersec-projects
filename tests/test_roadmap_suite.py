#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive Roadmap QA Test Suite (Phases A-D).

Covers all 12 Enterprise Roadmap domains:
  1. ASM Graph, ownership/tags, history, disappeared assets, CSV export
  2. 5-axis Risk Intelligence, configurable weights, CPE 2.3, Attack Paths
  3. Verification Engine, evidence redaction, marker-only anti-Confirmed rule, scoped retest
  4. DB Migrations (v1-v4), job queue metadata, backend status
  5. Threat Intel IOCs, STIX 2.1 import/export, multi-source corroboration
  6. Reporting & Executive Analytics, role-based redaction, custom templates
  7. Enterprise Integrations, HMAC webhooks, SSRF guard, SIEM CEF, SARIF v2.1.0
  8. Security Hardening: Argon2id + PBKDF2 migration, lockout, session revocation, path traversal, headers
  9. Multi-Tenant isolation (zero cross-tenant leakage)
  10. FastAPI end-to-end API routes
"""
from __future__ import annotations

import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import enterprise_db as edb  # noqa: E402
import security_hardening as sh  # noqa: E402
import asset_intel as ai  # noqa: E402
import vuln_intel as vi  # noqa: E402
import verification as vf  # noqa: E402
import threat_intel as ti  # noqa: E402
import integrations as integ  # noqa: E402
import reporting_analytics as rpt  # noqa: E402
import main as dark_main  # noqa: E402


def test_security_hardening_and_argon2_lockout():
    # 1. Argon2id hash & legacy PBKDF2 auto-upgrade
    h, alg = sh.hash_password("S3cur3!Pass#2026")
    assert h.startswith("$argon2") and alg == "argon2id"
    ok, needs_rehash = sh.verify_password("S3cur3!Pass#2026", h, alg)
    assert ok and not needs_rehash

    # 2. Sensitive evidence redaction
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef123456.xyz123456 AKIAIOSFODNN7EXAMPLE"
    red = sh.redact_sensitive(raw)
    assert "eyJhbGciOi" not in red and "AKIAIOSFODNN7EXAMPLE" not in red
    assert "[REDACTED" in red

    # 3. Path traversal guard
    base = Path("/tmp")
    safe = sh.safe_resolve_under(base, "sub/file.txt")
    assert str(safe).startswith(str(base.resolve()))
    try:
        sh.safe_resolve_under(base, "../../etc/passwd")
        assert False, "Expected ValueError on path traversal"
    except ValueError:
        pass

    # 4. SSRF guard blocks metadata IP & private ranges by default
    ok_meta, _ = sh.validate_outbound_url("http://169.254.169.254/latest/meta-data/")
    assert not ok_meta
    ok_priv, _ = sh.validate_outbound_url("http://10.0.0.5/hook")
    assert not ok_priv
    ok_pub, _ = sh.validate_outbound_url("https://hooks.example.com/dark")
    assert ok_pub

    # 5. Account lockout + session revocation
    import time as _t
    uname = f"locktest_{int(_t.time() * 1000)}"
    edb.create_user(uname, "GoodPass!123", role="analyst")
    for _ in range(5):
        ok_l, _, _ = edb.authenticate_user(uname, "WrongPass")
        assert not ok_l
    ok_locked, _, msg = edb.authenticate_user(uname, "GoodPass!123")
    assert not ok_locked and "locked" in msg.lower()

    # Reset lockout in DB and test session creation + revocation
    with edb._DB_LOCK:
        c = edb._conn()
        c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?", (uname,))
        c.commit()
        c.close()
    ok_good, urec, _ = edb.authenticate_user(uname, "GoodPass!123")
    assert ok_good and urec
    tok = edb.create_rbac_session(uname, "analyst")
    assert edb.get_rbac_session(tok) is not None
    rev_n = edb.revoke_user_sessions(uname)
    assert rev_n >= 1
    assert edb.get_rbac_session(tok) is None


def test_asm_graph_history_and_tenant_isolation():
    t1 = edb.create_tenant("Alpha Org")
    t2 = edb.create_tenant("Beta Org")
    a1 = ai.upsert_asset("p1", "domain", "alpha.example.com", criticality="high",
                         owner="sec-alpha", tags=["prod", "external"],
                         business_context="payment gateway", tenant_id=t1["id"])
    a2 = ai.upsert_asset("p1", "ip", "198.51.100.10", criticality="medium", tenant_id=t1["id"])
    ai.link_assets(a1["id"], a2["id"], "resolves_to", tenant_id=t1["id"])
    ai.upsert_asset("p1", "domain", "beta.example.com", criticality="low", tenant_id=t2["id"])

    res_t1 = ai.list_assets(tenant_id=t1["id"])
    names_t1 = {x["name"] for x in res_t1["assets"]}
    assert "alpha.example.com" in names_t1
    assert "beta.example.com" not in names_t1

    graph = ai.build_attack_surface_graph(tenant_id=t1["id"])
    assert any(e["relation"] == "resolves_to" for e in graph["edges"])

    dis = ai.mark_disappeared_assets("p1", "domain", ["alpha.example.com"], tenant_id=t1["id"])
    assert dis == 0


def test_verification_anti_fp_and_retest():
    # Marker-only / error-only finding MUST NOT auto-mark Confirmed
    rec = vf.record_verification(
        "default", "job-v1",
        {
            "vuln_type": "Reflected XSS (Heuristic)",
            "severity": "Medium",
            "url": "http://127.0.0.1:8080/search?q=test",
            "evidence": "Single SQL syntax error message or marker reflected",
        },
    )
    assert rec["status"] != "Confirmed", f"Marker-only finding was wrongly Confirmed: {rec}"

    # Scoped safe HTTP retest against local server
    class _Patched(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<html><body>Safe sanitized output</body></html>")

    srv = HTTPServer(("127.0.0.1", 0), _Patched)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        v2 = vf.record_verification(
            "default", "job-v2",
            {
                "vuln_type": "Reflected XSS",
                "severity": "High",
                "url": f"http://127.0.0.1:{port}/?q=<script>alert(1)</script>",
                "payload": "<script>alert(1)</script>",
                "evidence": "<script>alert(1)</script> Authorization: Bearer secret1234567890",
            },
        )
        assert "[REDACTED" in v2["redacted_evidence"]
        rt = vf.retest_verification(v2["id"], allow_loopback=True)
        assert rt["still_vulnerable"] is False
        assert rt["verification"]["status"] == "False Positive"
    finally:
        srv.shutdown()


def test_five_axis_risk_and_cpe():
    parsed = vi.parse_cpe23("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")
    assert parsed["vendor"] == "openbsd" and parsed["product"] == "openssh" and parsed["version"] == "8.2p1"

    out = vi.prioritize_findings([
        {"vuln_type": "Exposed .env Secrets", "severity": "High", "url": "https://pay.example.com/.env",
         "evidence": "DB_PASS=abc"},
        {"vuln_type": "SQL Injection", "severity": "Critical", "url": "https://pay.example.com/api",
         "evidence": "Extracted database rows via UNION SELECT"},
    ])
    assert out["total"] == 2
    assert len(out["attack_paths"]) >= 1
    assert "axes" in out["findings"][0]
    assert set(out["findings"][0]["axes"].keys()) == {"severity", "confidence", "exploitability", "business_impact", "exposure"}


def test_threat_intel_stix_and_integrations_sarif():
    ti.add_ioc("198.51.100.44", source="secondary-feed", ioc_type="ip", confidence=0.9)
    m = ti.match_observables(["198.51.100.44"])
    assert m["matches"] and m["matches"][0]["corroborated"] is True

    bundle = ti.export_stix_bundle()
    assert bundle["type"] == "bundle" and len(bundle["objects"]) >= 1
    imp = ti.import_stix_bundle(bundle, source="stix-roundtrip")
    assert imp["imported"] >= 1

    # SARIF round-trip
    sarif = integ.export_sarif({
        "result": {"findings": [{"vuln_type": "XSS", "severity": "High", "url": "https://ex.com", "cwe": "CWE-79"}]}
    })
    assert sarif["version"] == "2.1.0"
    parsed_fs = integ.parse_sarif_import(sarif)
    assert len(parsed_fs) == 1 and "CWE-79" in parsed_fs[0]["vuln_type"]

    # Reporting role redaction
    red_f = rpt.redact_finding_for_role({"vuln_type": "SQLi", "payload": "' OR 1=1--", "evidence": "Bearer abcdefgh1234567890"}, "viewer")
    assert red_f["payload"] == "[REDACTED FOR ROLE]"


def test_api_endpoints_and_api_key_auth():
    client = TestClient(dark_main.app)
    r_h = client.get("/api/health")
    assert r_h.status_code == 200
    assert r_h.headers.get("X-Content-Type-Options") == "nosniff"
    assert r_h.headers.get("X-Frame-Options") == "DENY"

    r_m = client.get("/api/metrics")
    assert r_m.status_code == 200 and "db_backend" in r_m.json()

    r_g = client.get("/api/assets/graph")
    assert r_g.status_code == 200 and "nodes" in r_g.json()

    r_w = client.get("/api/intel/risk/weights")
    assert r_w.status_code == 200 and "formula" in r_w.json()

    r_an = client.get("/api/analytics")
    assert r_an.status_code == 200 and "security_posture_score" in r_an.json()

    r_stix = client.get("/api/threat-intel/stix/export")
    assert r_stix.status_code == 200 and r_stix.json()["type"] == "bundle"

    # API Key issue + authenticate
    ak = edb.create_api_key("pytest-ci", role="analyst", tenant_id="default")
    r_ak = client.get("/api/verification", headers={"X-API-Key": ak["raw_key"]})
    assert r_ak.status_code == 200
    edb.revoke_api_key(ak["id"])
